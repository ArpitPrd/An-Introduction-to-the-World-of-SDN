import json
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.switches import Switches

import networkx as nx


class L2SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': Switches}

    def __init__(self, *args, **kwargs):
        super(L2SPF, self).__init__(*args, **kwargs)
        self.switches = kwargs['switches']
        self.mac_to_port = {}
        self.graph = nx.DiGraph()
        self.config = {}

        try:
            with open("config.json", 'r') as f:
                self.config = json.load(f)
        except (IOError, ValueError) as e:
            self.logger.error("Error loading config.json: %s. Using defaults.", e)
            self.config = {}

        self.weight_matrix = self.config.get("weight_matrix", [])
        self.ecmp = self.config.get("ecmp", False)
        self.logger.info("L2SPF Controller Started. ECMP is %s.", "enabled" if self.ecmp else "disabled")

    # ---------------------------
    # Ryu event handlers
    # ---------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Install table-miss flow entry to send packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected and table-miss installed.", datapath.id)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Handles link addition events. Correctly assigns weights for each
        direction of the link independently if a weight_matrix is provided.
        """
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no

        self.graph.add_node(src_dpid)
        self.graph.add_node(dst_dpid)

        cost_forward = 1  # Default cost for src -> dst
        cost_reverse = 1  # Default cost for dst -> src

        if self.weight_matrix:
            max_index = len(self.weight_matrix)
            # Ensure dpids are within bounds of the matrix (assuming 1-based dpid)
            if 1 <= src_dpid <= max_index and 1 <= dst_dpid <= max_index:
                # Look up forward cost
                w_fwd = self.weight_matrix[src_dpid - 1][dst_dpid - 1]
                cost_forward = w_fwd if (isinstance(w_fwd, (int, float)) and w_fwd != 0) else 1

                # Look up reverse cost
                w_rev = self.weight_matrix[dst_dpid - 1][src_dpid - 1]
                cost_reverse = w_rev if (isinstance(w_rev, (int, float)) and w_rev != 0) else 1

        # Add each directed edge with its specific weight
        self.graph.add_edge(src_dpid, dst_dpid, port=src_port, weight=cost_forward)
        self.graph.add_edge(dst_dpid, src_dpid, port=dst_port, weight=cost_reverse)

        self.logger.info("Added link: %s:%s (cost:%s) <-> %s:%s (cost:%s).",
                         src_dpid, src_port, cost_forward, dst_dpid, dst_port, cost_reverse)
        self.logger.debug("Current edges: %s", list(self.graph.edges(data=True)))

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Handles link deletion events to keep the topology graph up-to-date.
        """
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid

        try:
            self.graph.remove_edge(src_dpid, dst_dpid)
            self.graph.remove_edge(dst_dpid, src_dpid)
            self.logger.info("Removed link between switch %s and %s", src_dpid, dst_dpid)
        except nx.NetworkXError:
            self.logger.warning("Attempted to remove a non-existent link between %s and %s", src_dpid, dst_dpid)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        src_dpid = datapath.id

        # Learn source MAC address to avoid flooding next time.
        if src not in self.mac_to_port:
            self.mac_to_port[src] = (src_dpid, in_port)
            self.logger.info("Learned MAC %s at switch %s, port %s", src, src_dpid, in_port)

        if dst in self.mac_to_port:
            dst_dpid, dst_port = self.mac_to_port[dst]

            # If both hosts are on the same switch, install a direct flow.
            if src_dpid == dst_dpid:
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_src=src, eth_dst=dst)
                # Use a higher priority for more specific host-to-host rules
                self.add_flow(datapath, 20, match, actions)
                self.send_packet_out(datapath, msg, actions)
                self.logger.info("Installed local flow on switch %s for %s -> %s", src_dpid, src, dst)
                return

            # Compute all shortest paths and select one (or a random one for ECMP)
            try:
                paths = list(nx.all_shortest_paths(self.graph, source=src_dpid, target=dst_dpid, weight='weight'))
                if not paths:
                    raise nx.NetworkXNoPath

                selected_path = self.select_route(paths)
                self.logger.info("Selected path for %s -> %s: %s", src, dst, selected_path)

                # --- PROACTIVELY INSTALL FORWARD AND REVERSE PATHS ---
                self.install_path_flows(selected_path, src, dst, in_port, dst_port)

                # Send the initial packet out the first hop from the source switch
                first_hop_port = self.graph[src_dpid][selected_path[1]]['port']
                self.send_packet_out(datapath, msg, [parser.OFPActionOutput(first_hop_port)])

            except nx.NetworkXNoPath:
                self.logger.warning("No path from %s to %s found in graph. Flooding.", src_dpid, dst_dpid)
                self.flood_packet(datapath, msg)
        else:
            # Destination MAC is unknown, flood to discover it.
            self.logger.debug("Destination %s unknown. Flooding packet.", dst)
            self.flood_packet(datapath, msg)

    # ---------------------------
    # Flow and Packet helpers
    # ---------------------------
    def add_flow(self, datapath, priority, match, actions, idle_timeout=10, hard_timeout=0):
        """
        Adds a flow to a datapath with a default idle_timeout of 10 seconds.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def select_route(self, routes):
        """
        Selects a route from a list of equal-cost paths.
        Uses random choice if ECMP is enabled, otherwise picks the first path.
        """
        if self.ecmp and len(routes) > 1:
            return random.choice(routes)
        return routes[0]

    def flood_packet(self, datapath, msg):
        """
        Floods a packet on all ports except the one it came in on.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port')
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def send_packet_out(self, datapath, msg, actions):
        """
        Sends a packet out of a specific port on a datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port', ofproto.OFPP_CONTROLLER)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def install_path_flows(self, path, src_mac, dst_mac, src_host_port, dst_host_port):
        """
        Installs flows for both the forward and reverse paths of a communication stream.
        """
        # 1. Install FORWARD path (src -> dst)
        self.logger.info("Installing FORWARD path flows for %s -> %s", src_mac, dst_mac)
        for i in range(len(path) - 1):
            this_dpid = path[i]
            next_dpid = path[i + 1]
            out_port = self.graph[this_dpid][next_dpid]['port']
            dp = self.switches.dps.get(this_dpid)
            if dp:
                self.logger.info(f"Installed at switch: {this_dpid}")
                match = dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 20, match, actions)
        
        # Final hop flow on the destination switch
        dst_dp = self.switches.dps.get(path[-1])
        if dst_dp:
            match = dst_dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [dst_dp.ofproto_parser.OFPActionOutput(dst_host_port)]
            self.add_flow(dst_dp, 20, match, actions)

        # # 2. Install REVERSE path (dst -> src)
        self.logger.info("Installing REVERSE path flows for %s <- %s", src_mac, dst_mac)
        reverse_path = list(reversed(path))
        for i in range(len(reverse_path) - 1):
            this_dpid = reverse_path[i]
            next_dpid = reverse_path[i + 1]
            out_port = self.graph[this_dpid][next_dpid]['port']
            dp = self.switches.dps.get(this_dpid)
            if dp:
                # Note: src and dst are swapped for the reverse path match
                match = dp.ofproto_parser.OFPMatch(eth_src=dst_mac, eth_dst=src_mac)
                actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 20, match, actions)

        # Final hop flow on the original source switch
        src_dp = self.switches.dps.get(reverse_path[-1])
        if src_dp:
            match = src_dp.ofproto_parser.OFPMatch(eth_src=dst_mac, eth_dst=src_mac)
            actions = [src_dp.ofproto_parser.OFPActionOutput(src_host_port)]
            self.add_flow(src_dp, 20, match, actions)