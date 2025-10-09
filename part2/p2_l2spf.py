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
from ryu.topology.switches import Switches

import networkx as nx

class L2SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': Switches}

    def __init__(self, *args, **kwargs):
        super(L2SPF, self).__init__(*args, **kwargs)
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
        
        # **FIX 1: Corrected the number of expected links for this topology**
        self.EXPECTED_LINKS = 6

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected.", datapath.id)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no

        self.graph.add_node(src_dpid)
        self.graph.add_node(dst_dpid)

        if self.weight_matrix and max(src_dpid, dst_dpid) <= len(self.weight_matrix):
            edge_cost = self.weight_matrix[src_dpid - 1][dst_dpid - 1]
        else:
            edge_cost = 1
        
        self.graph.add_edge(src_dpid, dst_dpid, port=src_port, weight=edge_cost)
        self.graph.add_edge(dst_dpid, src_dpid, port=dst_port, weight=edge_cost)
        self.logger.info("Added link: %s <-> %s. Total edges: %d", src_dpid, dst_dpid, len(self.graph.edges))

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def select_route(self, routes):
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
        src_switch_id = datapath.id

        self.mac_to_port[src] = (src_switch_id, in_port)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.flood_packet(datapath, msg)
            return

        if dst in self.mac_to_port:
            dst_switch_id, dst_port = self.mac_to_port[dst]
            
            # **FIX 2: Re-enabled the stability check**
            # Do not attempt to calculate a path until the topology is fully discovered.
            if len(self.graph.edges) < self.EXPECTED_LINKS * 2:
                self.logger.warning("Topology not stable yet (%s/%s edges). Flooding packet.", 
                                  len(self.graph.edges), self.EXPECTED_LINKS * 2)
                self.flood_packet(datapath, msg)
                return

            if src_switch_id == dst_switch_id:
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, msg, actions)
                return

            try:
                paths = list(nx.all_shortest_paths(self.graph, source=src_switch_id, target=dst_switch_id, weight='weight'))
                if not paths: raise nx.NetworkXNoPath
                
                selected_path = self.select_route(paths)
                self.logger.info("Selected path for %s -> %s: %s", src, dst, selected_path)

                # Proactively install rules on all switches in the path
                for i in range(len(selected_path) - 1):
                    this_switch = selected_path[i]
                    next_switch = selected_path[i+1]
                    out_port = self.graph[this_switch][next_switch]['port']
                    
                    dp = self.switches.dps[this_switch]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(eth_dst=dst)
                    self.add_flow(dp, 1, match, actions)

                # Install the final rule on the destination switch
                dp = self.switches.dps[dst_switch_id]
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(dp, 1, match, actions)

                # Send the initial packet out the first hop
                first_hop_port = self.graph[src_switch_id][selected_path[1]]['port']
                self.send_packet_out(datapath, msg, [parser.OFPActionOutput(first_hop_port)])

            except nx.NetworkXNoPath:
                self.flood_packet(datapath, msg)
        else:
            self.flood_packet(datapath, msg)

    def flood_packet(self, datapath, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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

