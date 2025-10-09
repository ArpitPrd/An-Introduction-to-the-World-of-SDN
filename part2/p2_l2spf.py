import json
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.topology import event
from ryu.topology.switches import Switches

import networkx as nx


class L2SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': Switches}

    def __init__(self, *args, **kwargs):
        super(L2SPF, self).__init__(*args, **kwargs)
        self.switches = kwargs['switches']  # Switches context (holds datapaths)
        self.mac_to_port = {}               # MAC -> (dpid, port)
        self.config = {}
        try:
            with open("config.json", 'r') as f:
                self.config = json.load(f)
        except (IOError, ValueError) as e:
            self.logger.error("Error loading config.json: %s. Using defaults.", e)
            self.config = {}

        self.weight_matrix = self.config.get("weight_matrix", [])
        self.ecmp = self.config.get("ecmp", False)
        self.graph = nx.DiGraph()
        self.logger.info("L2SPF Controller Started. ECMP is %s.", "enabled" if self.ecmp else "disabled")

        # fallback for topology readiness if no weight_matrix present
        # If weight_matrix present, we'll compute expected directed edges from it.
        self.EXPECTED_LINKS = 6  # legacy fallback: number of undirected links
        # note: we intentionally do not hardcode *2 here. is_topology_ready handles directed edges.

    # ---------------------------
    # Topology readiness helpers
    # ---------------------------
    def expected_directed_edges_from_weight_matrix(self):
        """
        Count non-zero entries in weight_matrix. Each non-zero (i,j)
        means a directed edge i->j is expected.
        """
        if not self.weight_matrix:
            return None
        count = 0
        for i in range(len(self.weight_matrix)):
            for j in range(len(self.weight_matrix[i])):
                if self.weight_matrix[i][j] != 0:
                    count += 1
        return count

    def is_topology_ready(self):
        """
        Determine if topology is fully discovered.
        If weight_matrix is provided, use it to determine the expected directed edges.
        Otherwise, fall back to EXPECTED_LINKS * 2 (assuming undirected links represented both ways).
        """
        expected = self.expected_directed_edges_from_weight_matrix()
        if expected is None:
            expected = self.EXPECTED_LINKS * 2  # directed edges count
        current = len(self.graph.edges)
        self.logger.debug("Topology readiness check: %s/%s directed edges discovered.", current, expected)
        return current >= expected

    # ---------------------------
    # Ryu event handlers
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected and table-miss installed.", datapath.id)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Called for each link add event. We add BOTH directed edges to the DiGraph
        so path algorithms can work on directed edges.
        """
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no

        # ensure nodes exist
        self.graph.add_node(src_dpid)
        self.graph.add_node(dst_dpid)

        edge_cost = 1  # default
        # weight_matrix provided is 1-indexed conceptually (s1 => index 0).
        if self.weight_matrix:
            # safe bounds check: dpids are integers (1..N typically)
            max_index = len(self.weight_matrix)
            if 1 <= src_dpid <= max_index and 1 <= dst_dpid <= max_index:
                w = self.weight_matrix[src_dpid - 1][dst_dpid - 1]
                # treat zero as absent link; default cost = 1
                edge_cost = w if (isinstance(w, (int, float)) and w != 0) else 1

        # Add both directed edges with port info and weight
        self.graph.add_edge(src_dpid, dst_dpid, port=src_port, weight=edge_cost)
        self.graph.add_edge(dst_dpid, src_dpid, port=dst_port, weight=edge_cost)

        self.logger.info("Added link: %s:%s <-> %s:%s (cost %s). Total directed edges: %d",
                         src_dpid, src_port, dst_dpid, dst_port, edge_cost, len(self.graph.edges))

        # helpful debug: show edges when topology becomes ready
        if self.is_topology_ready():
            self.logger.info("Topology appears ready. Directed edges: %d", len(self.graph.edges))
            self.logger.info("Edges: %s", list(self.graph.edges(data=True)))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Main packet-in handler:
        - learn MAC -> (dpid, in_port)
        - handle ARP specially (learn + flood/reply forwarding)
        - compute shortest path (when topology ready) and proactively install flows on the path
        - if topology not ready: flood
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port', None)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ignore LLDP to avoid loops
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        src_switch_id = datapath.id

        # Learn source MAC
        self.mac_to_port[src] = (src_switch_id, in_port)
        self.logger.debug("Learned MAC %s at switch %s, port %s", src, src_switch_id, in_port)

        # Handle ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # ARP requests are broadcast at ethernet level; they help hosts learn each others' MACs.
            # For ARP replies, try to forward directly if we know mapping.
            if arp_pkt.opcode == arp.ARP_REPLY:
                # eth.dst on an ARP reply is usually the unicast MAC of requester; if we know it, forward.
                if dst in self.mac_to_port:
                    dst_switch_id, dst_port = self.mac_to_port[dst]
                    dp = self.switches.dps.get(dst_switch_id)
                    if dp:
                        actions = [parser.OFPActionOutput(dst_port)]
                        self.send_packet_out(dp, msg, actions)
                        self.logger.debug("Forwarded ARP reply to %s via switch %s port %s", dst, dst_switch_id, dst_port)
                        return
            # For ARP requests or unknown-case: flood
            self.logger.debug("Flooding ARP packet (opcode=%s).", arp_pkt.opcode)
            self.flood_packet(datapath, msg)
            return

        # If destination MAC known in controller mapping
        if dst in self.mac_to_port:
            dst_switch_id, dst_port = self.mac_to_port[dst]

            # If topology is not ready, flood instead of computing path
            if not self.is_topology_ready():
                expected = self.expected_directed_edges_from_weight_matrix() or (self.EXPECTED_LINKS * 2)
                self.logger.warning("Topology not stable yet (%s/%s directed edges). Flooding packet.", len(self.graph.edges), expected)
                self.flood_packet(datapath, msg)
                return

            # If both hosts on same switch: trivial local forwarding
            if src_switch_id == dst_switch_id:
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, msg, actions)
                self.logger.info("Installed local flow on switch %s for %s -> %s", src_switch_id, src, dst)
                return

            # Compute all shortest paths by weight, then select one (ECMP supported)
            try:
                paths = list(nx.all_shortest_paths(self.graph, source=src_switch_id,
                                                  target=dst_switch_id, weight='weight'))
                if not paths:
                    raise nx.NetworkXNoPath

                selected_path = self.select_route(paths)
                self.logger.info("Selected path for %s -> %s: %s", src, dst, selected_path)

                # Install flows for forward path (eth_dst == dst) on each hop
                for i in range(len(selected_path) - 1):
                    this_switch = selected_path[i]
                    next_switch = selected_path[i + 1]
                    out_port = self.graph[this_switch][next_switch]['port']
                    dp = self.switches.dps.get(this_switch)
                    if dp is None:
                        self.logger.warning("Datapath for switch %s not found; skipping flow install.", this_switch)
                        continue
                    actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                    match = dp.ofproto_parser.OFPMatch(eth_dst=dst)
                    self.add_flow(dp, 10, match, actions)
                    self.logger.debug("Installed forward flow on switch %s -> out_port %s for dst %s", this_switch, out_port, dst)

                # Install flow on destination switch (ensure final hop)
                dp_dst = self.switches.dps.get(dst_switch_id)
                if dp_dst:
                    actions = [dp_dst.ofproto_parser.OFPActionOutput(dst_port)]
                    match = dp_dst.ofproto_parser.OFPMatch(eth_dst=dst)
                    self.add_flow(dp_dst, 10, match, actions)
                    self.logger.debug("Installed final forward flow on dest switch %s port %s for dst %s", dst_switch_id, dst_port, dst)

                # ALSO install reverse path flows for return traffic (eth_dst == src)
                # Determine reverse path (shortest path from dst_switch -> src_switch)
                try:
                    reverse_paths = list(nx.all_shortest_paths(self.graph, source=dst_switch_id,
                                                               target=src_switch_id, weight='weight'))
                    reverse_selected = self.select_route(reverse_paths)
                    self.logger.debug("Selected reverse path for %s -> %s: %s", dst, src, reverse_selected)

                    for i in range(len(reverse_selected) - 1):
                        this_switch = reverse_selected[i]
                        next_switch = reverse_selected[i + 1]
                        out_port = self.graph[this_switch][next_switch]['port']
                        dp = self.switches.dps.get(this_switch)
                        if dp is None:
                            self.logger.warning("Datapath for switch %s not found; skipping reverse flow install.", this_switch)
                            continue
                        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                        match = dp.ofproto_parser.OFPMatch(eth_dst=src)
                        self.add_flow(dp, 10, match, actions)
                        self.logger.debug("Installed reverse flow on switch %s -> out_port %s for dst %s", this_switch, out_port, src)
                    # destination of reverse path is original source
                    dp_src = self.switches.dps.get(src_switch_id)
                    if dp_src:
                        actions = [dp_src.ofproto_parser.OFPActionOutput(in_port)]
                        match = dp_src.ofproto_parser.OFPMatch(eth_dst=src)
                        self.add_flow(dp_src, 10, match, actions)
                except nx.NetworkXNoPath:
                    self.logger.warning("No reverse path found %s -> %s. Skipping reverse flow install.", dst_switch_id, src_switch_id)

                # Send the initial packet out the first hop from the original datapath
                first_hop_port = self.graph[src_switch_id][selected_path[1]]['port']
                self.send_packet_out(datapath, msg, [parser.OFPActionOutput(first_hop_port)])
                self.logger.debug("Sent initial packet out of switch %s port %s", src_switch_id, first_hop_port)

            except nx.NetworkXNoPath:
                self.logger.warning("No path found in graph for %s -> %s. Flooding packet.", src, dst)
                self.flood_packet(datapath, msg)
        else:
            # Destination unknown to controller -> flood (learn will occur when reply comes)
            self.logger.debug("Destination %s unknown. Flooding packet.", dst)
            self.flood_packet(datapath, msg)

    # ---------------------------
    # Flow and Packet helpers
    # ---------------------------
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def select_route(self, routes):
        # simple ECMP: random choice among equal-cost shortest paths
        if self.ecmp and len(routes) > 1:
            return random.choice(routes)
        return routes[0]

    def flood_packet(self, datapath, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.send_packet_out(datapath, msg, actions)

    def send_packet_out(self, datapath, msg, actions):
        """
        Sends packet out via datapath. If the original packet was buffered on the switch,
        buffer_id may not be valid on a different switch — to be safe, we include the data
        and set buffer_id to NO_BUFFER.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # If the original msg had data, use it; otherwise we can't reconstruct
        data = msg.data if hasattr(msg, 'data') else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=msg.match.get('in_port', ofproto.OFPP_CONTROLLER),
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
