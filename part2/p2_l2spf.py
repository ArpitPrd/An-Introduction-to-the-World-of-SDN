import json
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.topology import event
from ryu.topology.api import get_switch
# **STEP 1: Import the Switches class**
from ryu.topology.switches import Switches

import networkx as nx

class L2SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # **STEP 2: Add the _CONTEXTS dictionary to declare dependency**
    _CONTEXTS = {'switches': Switches}

    def __init__(self, *args, **kwargs):
        super(L2SPF, self).__init__(*args, **kwargs)
        # **STEP 3: Get the switches instance from the context**
        self.switches = kwargs['switches']
        
        self.mac_to_port = {}
        
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected.", datapath.id)

    # Note: EventSwitchEnter is no longer needed as we get switch data from EventLinkAdd
    
    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no

        # Add nodes if they don't already exist
        self.graph.add_node(src_dpid)
        self.graph.add_node(dst_dpid)

        if self.weight_matrix and max(src_dpid, dst_dpid) <= len(self.weight_matrix):
            edge_cost = self.weight_matrix[src_dpid - 1][dst_dpid - 1]
        else:
            edge_cost = 1 # Default cost if matrix is not configured
        
        self.graph.add_edge(src_dpid, dst_dpid, port=src_port, weight=edge_cost)
        self.graph.add_edge(dst_dpid, src_dpid, port=dst_port, weight=edge_cost)
        self.logger.info("Added link from %s to %s with cost %s", src_dpid, dst_dpid, edge_cost)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def select_route(self, routes):
        """Selects a route based on the ECMP setting."""
        if self.ecmp and len(routes) > 1:
            return random.choice(routes)
        return routes[0]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port[src] = (dpid, in_port)

        # Handle ARP packets specifically
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.logger.info("ARP packet received from %s. Flooding.", src)
            self.flood_packet(datapath, msg)
            return

        if dst in self.mac_to_port:
            dst_dpid, dst_port = self.mac_to_port[dst]
            
            if dpid == dst_dpid:
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, msg, actions)
                return

            try:
                paths = list(nx.all_shortest_paths(self.graph, source=dpid, target=dst_dpid, weight='weight'))
                if not paths: raise nx.NetworkXNoPath
                
                selected_path = self.select_route(paths)
                self.logger.info("Selected path for %s -> %s: %s", src, dst, selected_path)

                # Install rules on all switches in the path
                for i in range(len(selected_path) - 1):
                    this_dpid = selected_path[i]
                    next_dpid = selected_path[i+1]
                    out_port = self.graph[this_dpid][next_dpid]['port']
                    
                    # Use the switches context to get the datapath object
                    dp = self.switches.dps[this_dpid]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(eth_dst=dst)
                    self.add_flow(dp, 1, match, actions)

                # Install the final rule on the destination switch
                dp = self.switches.dps[dst_dpid]
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(dp, 1, match, actions)

                # Send the initial packet out the first hop
                first_hop_port = self.graph[dpid][selected_path[1]]['port']
                self.send_packet_out(datapath, msg, [parser.OFPActionOutput(first_hop_port)])

            except nx.NetworkXNoPath:
                self.logger.warning("No path from switch %s to %s. Flooding.", dpid, dst_dpid)
                self.flood_packet(datapath, msg)
        else:
            self.flood_packet(datapath, msg)

    def flood_packet(self, datapath, msg):
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.send_packet_out(datapath, msg, actions)

    def send_packet_out(self, datapath, msg, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

