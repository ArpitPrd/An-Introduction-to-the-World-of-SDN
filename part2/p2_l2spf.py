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
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp

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
        self.taken = False
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
            return

        dst_mac = eth.dst
        src_mac = eth.src
        src_dpid = datapath.id

        # Learn source MAC address to avoid flooding next time.
        if src_mac not in self.mac_to_port:
            self.mac_to_port[src_mac] = (src_dpid, in_port)
            self.logger.info("Learned MAC %s at switch %s, port %s", src_mac, src_dpid, in_port)
            
        # --- START OF MODIFIED SECTION ---

        # We will only apply SPF routing for IP packets.
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ipv4_pkt and tcp_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            
            self.logger.info("PacketIn: TCP %s:%s -> %s:%s on switch %s", src_ip, src_port, dst_ip, dst_port, src_dpid)

            if dst_mac in self.mac_to_port:
                dst_dpid, dst_host_port = self.mac_to_port[dst_mac]

                if src_dpid == dst_dpid:
                    self.logger.info("Packet is at its destination switch %s. Installing local delivery flow.", src_dpid)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=6, # TCP
                                            ipv4_src=src_ip,
                                            ipv4_dst=dst_ip,
                                            tcp_src=src_port,
                                            tcp_dst=dst_port)
                    actions = [parser.OFPActionOutput(dst_host_port)]
                    self.add_flow(datapath, 20, match, actions)
                    self.send_packet_out(datapath, msg, actions)
                    return # Exit the handler early

                try:
                    paths = list(nx.all_shortest_paths(self.graph, source=src_dpid, target=dst_dpid, weight='weight'))
                    if not paths:
                        raise nx.NetworkXNoPath

                    selected_path = self.select_route(paths)
                    self.logger.info("Selected path for flow %s:%s -> %s:%s is %s", src_ip, src_port, dst_ip, dst_port, selected_path)
                    
                    # Pass all flow details to the installation function
                    self.install_path_flows(selected_path, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, in_port, dst_host_port)

                    # Send the initial packet out
                    first_hop_port = self.graph[src_dpid][selected_path[1]]['port']
                    self.send_packet_out(datapath, msg, [parser.OFPActionOutput(first_hop_port)])

                except nx.NetworkXNoPath:
                    self.logger.warning("No path from %s to %s found in graph. Flooding.", src_dpid, dst_dpid)
                    self.flood_packet(datapath, msg)
            else:
                self.logger.debug("Destination %s unknown. Flooding packet.", dst_mac)
                self.flood_packet(datapath, msg)
        
        # If the packet is not TCP/IP (e.g., ARP), use the old flooding logic.
        elif dst_mac not in self.mac_to_port:
            self.logger.debug("Destination %s unknown (Non-IP). Flooding packet.", dst_mac)
            self.flood_packet(datapath, msg)
        # --- END OF MODIFIED SECTION ---

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
        if self.taken:
            self.taken = False
            return routes[0]
        self.taken = True
        return routes[1]
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

    def install_path_flows(self, path, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, src_host_port, dst_host_port):
        """
        Installs flows for both the forward and reverse paths of a communication stream
        using a 5-tuple match for IP traffic.
        """
        # 1. Install FORWARD path (src -> dst)
        self.logger.info("Installing FORWARD path flows for %s:%s -> %s:%s", src_ip, src_port, dst_ip, dst_port)
        for i in range(len(path) - 1):
            this_dpid = path[i]
            next_dpid = path[i + 1]
            out_port = self.graph[this_dpid][next_dpid]['port']
            dp = self.switches.dps.get(this_dpid)
            if dp:
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=6, # 6 for TCP
                                        ipv4_src=src_ip,
                                        ipv4_dst=dst_ip,
                                        tcp_src=src_port,
                                        tcp_dst=dst_port)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 20, match, actions)
        
        # Final hop flow on the destination switch
        dst_dp = self.switches.dps.get(path[-1])
        if dst_dp:
            parser = dst_dp.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6,
                                    ipv4_src=src_ip,
                                    ipv4_dst=dst_ip,
                                    tcp_src=src_port,
                                    tcp_dst=dst_port)
            actions = [parser.OFPActionOutput(dst_host_port)]
            self.add_flow(dst_dp, 20, match, actions)

        # 2. Install REVERSE path (dst -> src)
        self.logger.info("Installing REVERSE path flows for %s:%s <- %s:%s", src_ip, src_port, dst_ip, dst_port)
        reverse_path = list(reversed(path))
        for i in range(len(reverse_path) - 1):
            this_dpid = reverse_path[i]
            next_dpid = reverse_path[i + 1]
            out_port = self.graph[this_dpid][next_dpid]['port']
            dp = self.switches.dps.get(this_dpid)
            if dp:
                parser = dp.ofproto_parser
                # Note: src and dst are swapped for the reverse path match
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=6,
                                        ipv4_src=dst_ip,
                                        ipv4_dst=src_ip,
                                        tcp_src=dst_port,
                                        tcp_dst=src_port)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 20, match, actions)

        # Final hop flow on the original source switch
        src_dp = self.switches.dps.get(reverse_path[-1])
        if src_dp:
            parser = src_dp.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6,
                                    ipv4_src=dst_ip,
                                    ipv4_dst=src_ip,
                                    tcp_src=dst_port,
                                    tcp_dst=src_port)
            actions = [parser.OFPActionOutput(src_host_port)]
            self.add_flow(src_dp, 20, match, actions)