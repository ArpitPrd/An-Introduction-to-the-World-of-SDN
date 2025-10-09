import json
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch

import networkx as nx

class L2SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2SPF, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # **FIXED**: Correctly load the configuration file
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

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        dpid = ev.switch.dp.id
        self.graph.add_node(dpid)
        self.logger.info("Added Switch %s to the network graph.", dpid)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        src_id = ev.link.src.dpid
        dst_id = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no

        if self.weight_matrix and max(src_id, dst_id) <= len(self.weight_matrix):
            edge_cost = self.weight_matrix[src_id - 1][dst_id - 1]
        else:
            edge_cost = 1 # Default cost
        
        self.graph.add_edge(src_id, dst_id, port=src_port, weight=edge_cost)
        self.graph.add_edge(dst_id, src_id, port=dst_port, weight=edge_cost)
        self.logger.info("Added link from %s to %s with cost %s", src_id, dst_id, edge_cost)

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
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        src_switch_id = datapath.id

        self.mac_to_port[src] = (src_switch_id, in_port)

        if dst in self.mac_to_port:
            dst_switch_id, dst_out_port = self.mac_to_port[dst]

            if src_switch_id == dst_switch_id:
                # **FIXED**: Correctly install flow and send packet for same-switch case
                self.logger.info("Both hosts on same switch %s", src_switch_id)
                actions = [parser.OFPActionOutput(dst_out_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, msg, actions)
                return # End processing here

            try:
                paths = list(nx.all_shortest_paths(self.graph, source=src_switch_id, target=dst_switch_id, weight="weight"))
                selected_route = self.select_route(paths)
                self.logger.info("Selected route for %s -> %s: %s", src, dst, selected_route)

                # Install rules on intermediate switches
                for i in range(len(selected_route) - 1):
                    this_switch_dpid = selected_route[i]
                    next_switch_dpid = selected_route[i+1]
                    out_port = self.graph[this_switch_dpid][next_switch_dpid]["port"]
                    this_switch_datapath = get_switch(self, this_switch_dpid)[0].dp
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(eth_dst=dst)
                    self.add_flow(this_switch_datapath, 1, match, actions)

                # Install rule on the final switch to reach the host
                final_switch_datapath = get_switch(self, dst_switch_id)[0].dp
                actions = [parser.OFPActionOutput(dst_out_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(final_switch_datapath, 1, match, actions)

                # Send the initial packet out along the first hop
                first_hop_port = self.graph[src_switch_id][selected_route[1]]["port"]
                actions_for_first_packet = [parser.OFPActionOutput(first_hop_port)]
                self.send_packet_out(datapath, msg, actions_for_first_packet)

            except (nx.NetworkXNoPath, KeyError):
                self.logger.warning("No path from %s to %s. Flooding.", src_switch_id, dst_switch_id)
                self.flood_packet(datapath, msg)
        
        else:
            # self.logger.info("Destination %s unknown. Flooding packet.", dst)
            self.flood_packet(datapath, msg)

    # **FIXED**: Removed the old, conflicting logic from the end of the function

    def flood_packet(self, datapath, msg):
        """Helper to flood a packet."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.send_packet_out(datapath, msg, actions)

    def send_packet_out(self, datapath, msg, actions):
        """Helper to send a PacketOut message."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

