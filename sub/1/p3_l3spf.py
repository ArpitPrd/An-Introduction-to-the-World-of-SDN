from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event, switches
import networkx as nx
import json

class L3SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'switches': switches.Switches,
    }

    def __init__(self, *args, **kwargs):
        super(L3SPF, self).__init__(*args, **kwargs)
        self.switches_app = kwargs['switches']
        self.graph = nx.Graph()
        self.arp_table = {}
        self.config = {}

        try:
            with open('p3_config.json', 'r') as f:
                self.config = json.load(f)
        except (IOError, ValueError) as e:
            self.logger.error("Error loading or parsing p3_config.json: %s.", e)
        
        self.populate_arp_table()
        self.build_topology()

    def populate_arp_table(self):
        for host in self.config.get('hosts', []):
            self.arp_table[host['ip']] = host['mac']
        for switch in self.config.get('switches', []):
            for interface in switch.get('intesfaces', []): # Handles typo
                self.arp_table[interface['ip']] = interface['mac']
        self.logger.info("ARP table populated from config.")

    def build_topology(self):
        for switch in self.config.get("switches", []):
            self.graph.add_node(switch["dpid"])
        for link in self.config.get("links", []):
            src_dpid = int(link['ssc'][1:]) # Handles typo
            dst_dpid = int(link['dst'][1:])
            self.graph.add_edge(src_dpid, dst_dpid, weight=link.get('cost', 1))
        self.logger.info("Topology built. Nodes: %s, Edges: %s", self.graph.nodes(), self.graph.edges(data=True))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected.", datapath.id)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=30, hard_timeout=60)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, msg.match['in_port'], pkt, eth)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(msg, datapath, pkt, eth)

    def handle_arp(self, datapath, port, pkt, eth):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode != arp.ARP_REQUEST: return
        dst_ip = arp_pkt.dst_ip
        if dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            p = packet.Packet()
            p.add_protocol(ethernet.ethernet(dst=eth.src, src=dst_mac, ethertype=ether_types.ETH_TYPE_ARP))
            p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst_mac, src_ip=dst_ip, dst_mac=eth.src, dst_ip=arp_pkt.src_ip))
            p.serialize()
            actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            self.send_packet_out(datapath, datapath.ofproto.OFP_NO_BUFFER, datapath.ofproto.OFPP_CONTROLLER, actions, p.data)
            self.logger.info("Sent ARP reply for %s", dst_ip)

    def handle_ip(self, msg, datapath, pkt, eth):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
        src_dpid = datapath.id

        dst_host_info = next((h for h in self.config['hosts'] if h['ip'] == dst_ip), None)
        if not dst_host_info: return
        dst_dpid = int(dst_host_info['switch'][1:])

        try:
            path = nx.shortest_path(self.graph, source=src_dpid, target=dst_dpid, weight='weight')
            self.logger.info("Path for %s -> %s: %s", src_ip, dst_ip, path)
        except (nx.NodeNotFound, nx.NetworkXNoPath) as e:
            self.logger.error("Could not find path: %s", e)
            return

        self.install_path_flows(path, src_ip, dst_ip)
        
        out_port, new_dst_mac = self.get_forwarding_info(src_dpid, path, dst_ip)
        
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionSetField(eth_dst=new_dst_mac),
                   parser.OFPActionOutput(out_port)]

        self.send_packet_out(datapath, msg.buffer_id, msg.match['in_port'], actions, msg.data)


    def install_path_flows(self, path, src_ip, dst_ip):
        # Install forward path (src -> dst)
        for i, dpid in enumerate(path):
            dp = self.switches_app.dps.get(dpid)
            if not dp: continue
            
            out_port, new_dst_mac = self.get_forwarding_info(dpid, path[i:], dst_ip)

            if out_port and new_dst_mac:
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                actions = [parser.OFPActionSetField(eth_dst=new_dst_mac),
                           parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 1, match, actions)

        # Install reverse path (dst -> src)
        rev_path = list(reversed(path))
        for i, dpid in enumerate(rev_path):
            dp = self.switches_app.dps.get(dpid)
            if not dp: continue

            out_port, new_dst_mac = self.get_forwarding_info(dpid, rev_path[i:], src_ip)
            
            if out_port and new_dst_mac:
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)
                actions = [parser.OFPActionSetField(eth_dst=new_dst_mac),
                           parser.OFPActionOutput(out_port)]
                self.add_flow(dp, 1, match, actions)

    # --- THIS FUNCTION IS NOW CORRECT ---
    def get_forwarding_info(self, dpid, sub_path, final_destination_ip):
        if len(sub_path) > 1: # It's a switch-to-switch link
            next_dpid = sub_path[1]
            out_port = self.get_port_to_switch(dpid, next_dpid)
            new_dst_mac = self.get_switch_interface_mac(next_dpid, dpid)
            return out_port, new_dst_mac
        else: # It's the final hop to the host
            out_port = self.get_port_to_host(dpid, final_destination_ip)
            new_dst_mac = self.arp_table.get(final_destination_ip)
            return out_port, new_dst_mac
    
    def get_port_to_switch(self, src_dpid, dst_dpid):
        for switch in self.config['switches']:
            if switch['dpid'] == src_dpid:
                for iface in switch.get('intesfaces', []): 
                    if iface.get('neighbos') == f's{dst_dpid}':
                        return int(iface['name'].split('-eth')[1])
        return None

    def get_switch_interface_mac(self, dpid, neighbor_dpid):
        for switch in self.config['switches']:
            if switch['dpid'] == dpid:
                for iface in switch.get('intesfaces', []):
                    if iface.get('neighbos') == f's{neighbor_dpid}':
                        return iface['mac']
        return None

    def get_port_to_host(self, dpid, host_ip):
        host_info = next((h for h in self.config['hosts'] if h['ip'] == host_ip), None)
        if host_info and int(host_info['switch'][1:]) == dpid:
            for switch in self.config['switches']:
                if switch['dpid'] == dpid:
                    for iface in switch.get('intesfaces', []):
                        if iface.get('neighbos') == host_info['name']:
                            return int(iface['name'].split('-eth')[1])
        return None

    def send_packet_out(self, datapath, buffer_id, in_port, actions, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=buffer_id if buffer_id != ofproto.OFP_NO_BUFFER else ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)