# File: p4_l3spf_lf.py (Final Working Version)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event, switches
import networkx as nx
import json
import time

class L3SPFLinkFailureController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(L3SPFLinkFailureController, self).__init__(*args, **kwargs)
        self.switches_app = kwargs['switches']
        self.graph = nx.Graph()
        self.arp_table = {}
        self.config = {}
        self.logger.info("--- L3 SPF Controller Initializing (Final Working Version) ---")

        try:
            with open('p4_config.json', 'r') as f: self.config = json.load(f)
        except Exception as e:
            self.logger.error("FATAL: Could not load p4_config.json: %s", e); raise e
        
        self.populate_arp_table()
        self.build_static_topology()

    def populate_arp_table(self):
        for host in self.config.get('hosts', []): self.arp_table[host['ip']] = host['mac']
        for switch in self.config.get('switches', []):
            for interface in switch.get('interfaces', []): self.arp_table[interface['ip']] = interface['mac']
        self.logger.info("ARP table populated with %d entries.", len(self.arp_table))

    def build_static_topology(self):
        for switch in self.config.get("switches", []): self.graph.add_node(switch["dpid"])
        for link in self.config.get("links", []):
            src, dst = int(link['src'][1:]), int(link['dst'][1:])
            self.graph.add_edge(src, dst, weight=link.get('cost', 1))
        self.logger.info("Static topology built. Nodes: %s, Edges: %s", self.graph.nodes(), self.graph.edges(data=True))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        match = dp.ofproto_parser.OFPMatch()
        actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER, dp.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions, "Default-Miss-Entry")
        self.logger.info("Switch s%s connected. Installed table-miss flow.", dp.id)

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src, dst = ev.link.src.dpid, ev.link.dst.dpid
        if self.graph.has_edge(src, dst):
            self.graph.remove_edge(src, dst)
            self.logger.info(f"*** [TIME: {time.time():.4f}] Link DOWN: s{src}<->s{dst}. Clearing flows.")
            self.clear_all_flows()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        src, dst = ev.link.src.dpid, ev.link.dst.dpid
        cost = next((l.get('cost', 1) for l in self.config.get("links",[]) if (f"s{src}"==l['src'] and f"s{dst}"==l['dst']) or (f"s{dst}"==l['src'] and f"s{src}"==l['dst'])), 1)
        self.graph.add_edge(src, dst, weight=cost)
        self.logger.info(f"*** [TIME: {time.time():.4f}] Link UP: s{src}<->s{dst} with cost {cost}.")

    def clear_all_flows(self):
        for dp in self.switches_app.dps.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, priority=1,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch())
            dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg; pkt = packet.Packet(msg.data); eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        
        if eth.ethertype == ether_types.ETH_TYPE_ARP: self.handle_arp(msg)
        elif eth.ethertype == ether_types.ETH_TYPE_IP: self.handle_ip(msg)

    def handle_arp(self, msg):
        dp = msg.datapath; in_port = msg.match['in_port']; pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet); arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt or arp_pkt.opcode != arp.ARP_REQUEST: return
        
        req_ip = arp_pkt.dst_ip
        if req_ip in self.arp_table:
            self.logger.info("ARP Request on s%d for known IP %s. Replying.", dp.id, req_ip)
            reply_mac = self.arp_table[req_ip]
            p = packet.Packet()
            p.add_protocol(ethernet.ethernet(dst=eth_pkt.src, src=reply_mac, ethertype=ether_types.ETH_TYPE_ARP))
            p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_mac, src_ip=req_ip, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            p.serialize()
            actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
            out = dp.ofproto_parser.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                                                 in_port=dp.ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
            dp.send_msg(out)

    def handle_ip(self, msg):
        dp = msg.datapath; pkt = packet.Packet(msg.data); ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt: return

        src_dpid = dp.id
        src_ip, dst_ip = ip_pkt.src, ip_pkt.dst

        dst_host = next((h for h in self.config['hosts'] if h['ip'] == dst_ip), None)
        if not dst_host: return
        dst_dpid = int(dst_host['switch'][1:])

        try:
            path = nx.shortest_path(self.graph, source=src_dpid, target=dst_dpid, weight='weight')
            self.logger.info("s%d: Path for %s -> %s is %s", src_dpid, src_ip, dst_ip, '->'.join(f's{p}' for p in path))
        except (nx.NodeNotFound, nx.NetworkXNoPath) as e:
            self.logger.error("s%d: No path found to %s: %s", src_dpid, dst_ip, e); return

        out_port, new_mac = self.get_forwarding_info(src_dpid, path, dst_ip)
        
        if out_port and new_mac:
            # Install FORWARD flow rule
            match = dp.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            actions = [dp.ofproto_parser.OFPActionSetField(eth_dst=new_mac), dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions, f"FWD_to_{dst_ip}")

            # Send the packet out to the next hop
            out = dp.ofproto_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'], actions=actions, data=msg.data)
            dp.send_msg(out)

    def get_forwarding_info(self, dpid, sub_path, final_ip):
        if len(sub_path) > 1: # Intermediate hop
            next_dpid = sub_path[1]
            out_port = self.get_port_to_switch(dpid, next_dpid)
            new_mac = self.get_switch_interface_mac(next_dpid, dpid)
            return out_port, new_mac
        else: # Final hop
            out_port = self.get_port_to_host(dpid, final_ip)
            new_mac = self.arp_table.get(final_ip)
            return out_port, new_mac

    def get_port_to_switch(self, src_dpid, dst_dpid):
        for s in self.config['switches']:
            if s['dpid'] == src_dpid:
                for iface in s.get('interfaces', []): 
                    if iface.get('neighbor') == f's{dst_dpid}': return int(iface['name'].split('-eth')[1])
        return None

    def get_switch_interface_mac(self, dpid, neighbor_dpid):
        for s in self.config['switches']:
            if s['dpid'] == dpid:
                for iface in s.get('interfaces', []):
                    if iface.get('neighbor') == f's{neighbor_dpid}': return iface['mac']
        return None

    def get_port_to_host(self, dpid, host_ip):
        host = next((h for h in self.config['hosts'] if h['ip'] == host_ip), None)
        if host and int(host['switch'][1:]) == dpid:
            for s in self.config['switches']:
                if s['dpid'] == dpid:
                    for iface in s.get('interfaces', []):
                        if iface.get('neighbor') == host['name']: return int(iface['name'].split('-eth')[1])
        return None

    def add_flow(self, datapath, priority, match, actions, name=""):
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=30, hard_timeout=90)
        datapath.send_msg(mod)
        self.logger.info("Flow installed on s%d: [%s] Match: %s, Actions: %s", datapath.id, name, match, actions)