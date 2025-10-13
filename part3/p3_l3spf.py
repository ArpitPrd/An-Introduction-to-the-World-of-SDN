import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.switches import Switches
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
import ipaddress

import networkx as nx

class L3SPF(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': Switches}

    def __init__(self, *args, **kwargs):
        super(L3SPF, self).__init__(*args, **kwargs)
        self.switches = kwargs['switches']
        self.graph = nx.DiGraph()
        
        # --- L3 specific data structures ---
        self.arp_table = {}  # IP -> MAC mapping
        self.host_info = {}  # IP -> (DPID, Port) mapping
        self.switch_info = {} # DPID -> Interface info
        self.mac_to_port = {} # MAC -> (DPID, Port) mapping for hosts

        self.logger.info("L3SPF Controller Started.")
        self._load_config()

    def _load_config(self):
        """Loads and parses the L3 configuration file."""
        try:
            with open("l3_config.json", 'r') as f:
                config = json.load(f)
        except (IOError, ValueError) as e:
            self.logger.error("Error loading l3_config.json: %s. Aborting.", e)
            return

        # Load host information and populate ARP table
        for host in config.get("hosts", []):
            self.arp_table[host['ip']] = host['mac']
            self.host_info[host['ip']] = {
                'dpid': self._dpid_from_name(config, host['switch']),
                'mac': host['mac']
            }

        # Load switch interface information
        for switch in config.get("switches", []):
            dpid = switch['dpid']
            self.switch_info[dpid] = {}
            for interface in switch.get("interfaces", []):
                self.arp_table[interface['ip']] = interface['mac']
                self.switch_info[dpid][interface['subnet']] = {
                    'ip': interface['ip'],
                    'mac': interface['mac'],
                    'name': interface['name']
                }

        # Build graph with weights from config
        for link in config.get("links", []):
            src_dpid = self._dpid_from_name(config, link['src'])
            dst_dpid = self._dpid_from_name(config, link['dst'])
            cost = link.get('cost', 1)
            if src_dpid and dst_dpid:
                self.graph.add_edge(src_dpid, dst_dpid, weight=cost)
                self.graph.add_edge(dst_dpid, src_dpid, weight=cost) # Assuming bidirectional links
        
        self.logger.info("Loaded L3 configuration. ARP table and topology graph built.")
        self.logger.debug("ARP Table: %s", self.arp_table)
        self.logger.debug("Graph Edges: %s", list(self.graph.edges(data=True)))

    def _dpid_from_name(self, config, name):
        """Helper to get DPID from a switch name (e.g., 'r1')."""
        for switch in config.get("switches", []):
            if switch['name'] == name:
                return switch['dpid']
        return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install a high-priority rule to drop packets with TTL <= 1
        match_ttl = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_ttl=1)
        self.add_flow(datapath, 100, match_ttl, []) # Empty actions = drop
        
        self.logger.info("Switch %s connected. Table-miss and TTL drop rules installed.", datapath.id)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """Discovers port numbers for links defined in the config."""
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        
        if self.graph.has_edge(src_dpid, dst_dpid):
            self.graph[src_dpid][dst_dpid]['port'] = src_port
            self.logger.info("Discovered link: %s -> %s on port %s", src_dpid, dst_dpid, src_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Learn host location (MAC, DPID, Port) for the first time
        if eth_pkt.src not in self.mac_to_port:
             # Check if MAC belongs to a host from our config
            for host_ip, info in self.host_info.items():
                if info['mac'] == eth_pkt.src:
                    self.mac_to_port[eth_pkt.src] = (datapath.id, in_port)
                    # Update host_info with the port
                    self.host_info[host_ip]['port'] = in_port
                    self.logger.info("Learned Host %s (%s) at switch %s, port %s", 
                                     host_ip, eth_pkt.src, datapath.id, in_port)
                    break

        # --- Handle ARP packets ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth_pkt, arp_pkt)
            return

        # --- Handle IP packets ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self._handle_ipv4(datapath, in_port, eth_pkt, ipv4_pkt, msg.data)

    def _handle_arp(self, datapath, port, eth_pkt, arp_pkt):
        """Handles ARP requests by crafting synthetic replies."""
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        req_ip = arp_pkt.dst_ip
        src_ip = arp_pkt.src_ip
        self.logger.info("ARP Request: Who has %s? Tell %s", req_ip, src_ip)

        # Look up the requested IP in our static ARP table
        dst_mac = self.arp_table.get(req_ip)
        if dst_mac is None:
            self.logger.warning("ARP: No MAC found for IP %s. Dropping.", req_ip)
            return
        
        # Craft ARP reply
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                          dst=eth_pkt.src,
                                          src=dst_mac))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                               src_mac=dst_mac,
                               src_ip=req_ip,
                               dst_mac=arp_pkt.src_mac,
                               dst_ip=arp_pkt.src_ip))
        p.serialize()

        # Send ARP reply back out the port it came from
        actions = [datapath.ofproto_parser.OFPActionOutput(port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                   buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                   in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                   actions=actions, data=p.data)
        datapath.send_msg(out)
        self.logger.info("Sent ARP Reply: %s is at %s", req_ip, dst_mac)

    def _handle_ipv4(self, datapath, in_port, eth_pkt, ipv4_pkt, data):
        """Handles IP packets by calculating paths and installing L3 flow rules."""
        src_dpid = datapath.id
        dst_ip = ipv4_pkt.dst
        
        if dst_ip not in self.host_info:
            self.logger.warning("IP packet to unknown host %s. Dropping.", dst_ip)
            return
            
        dst_dpid = self.host_info[dst_ip]['dpid']

        # If packet is already at the destination switch, just deliver it
        if src_dpid == dst_dpid:
            self.logger.debug("Packet at destination switch %s for %s", src_dpid, dst_ip)
            self._install_final_hop_flow(datapath, dst_ip)
            # We need to send this packet out manually after installing the rule
            self._send_packet_out_l3(datapath, data, self.host_info[dst_ip]['port'], 
                                   self._get_router_mac_for_ip(dst_ip),
                                   self.host_info[dst_ip]['mac'])
            return

        # Calculate shortest path and install flows
        try:
            path = nx.shortest_path(self.graph, source=src_dpid, target=dst_dpid, weight='weight')
            self.logger.info("Shortest path for %s -> %s: %s", ipv4_pkt.src, dst_ip, path)
            self.install_l3_path_flows(path, dst_ip)
            
            # Send the current packet out the first hop
            next_hop_dpid = path[1]
            out_port = self.graph[src_dpid][next_hop_dpid]['port']
            
            # Determine correct MACs for the first hop
            src_mac = self._get_interface_mac(src_dpid, next_hop_dpid)
            dst_mac = self._get_interface_mac(next_hop_dpid, src_dpid)

            if src_mac and dst_mac:
                 self._send_packet_out_l3(datapath, data, out_port, src_mac, dst_mac)

        except (nx.NetworkXNoPath, KeyError) as e:
            self.logger.error("No path or port found from %s to %s for IP %s: %s. Dropping packet.",
                              src_dpid, dst_dpid, dst_ip, e)

    def install_l3_path_flows(self, path, dst_ip):
        """Installs L3 forwarding rules along a calculated path for a given dst_ip."""
        # Install rules for all hops except the last one
        for i in range(len(path) - 1):
            this_dpid = path[i]
            next_dpid = path[i+1]
            dp = self.switches.dps.get(this_dpid)

            if dp:
                out_port = self.graph[this_dpid][next_dpid]['port']
                new_eth_src = self._get_interface_mac(this_dpid, next_dpid)
                new_eth_dst = self._get_interface_mac(next_dpid, this_dpid)

                if new_eth_src and new_eth_dst:
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                    actions = [
                        parser.OFPActionDecNwTtl(),
                        parser.OFPActionSetField(eth_src=new_eth_src),
                        parser.OFPActionSetField(eth_dst=new_eth_dst),
                        parser.OFPActionOutput(out_port)
                    ]
                    self.add_flow(dp, 10, match, actions)
        
        # Install rule for the final hop (to the host)
        last_hop_dpid = path[-1]
        last_hop_dp = self.switches.dps.get(last_hop_dpid)
        if last_hop_dp:
            self._install_final_hop_flow(last_hop_dp, dst_ip)

    def _install_final_hop_flow(self, datapath, dst_ip):
        """Installs the flow rule for the last router to deliver packet to a host."""
        parser = datapath.ofproto_parser
        host_port = self.host_info[dst_ip]['port']
        host_mac = self.host_info[dst_ip]['mac']
        router_mac = self._get_router_mac_for_ip(dst_ip)
        
        if host_port and host_mac and router_mac:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            actions = [
                parser.OFPActionDecNwTtl(),
                parser.OFPActionSetField(eth_src=router_mac),
                parser.OFPActionSetField(eth_dst=host_mac),
                parser.OFPActionOutput(host_port)
            ]
            self.add_flow(datapath, 10, match, actions)
            self.logger.debug("Installed final hop flow on %s for %s", datapath.id, dst_ip)

    def _send_packet_out_l3(self, datapath, data, out_port, src_mac, dst_mac):
        """Sends a packet out with L3 actions applied."""
        parser = datapath.ofproto_parser
        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=datapath.ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        datapath.send_msg(out)

    def _get_interface_mac(self, src_dpid, dst_dpid):
        """Finds the MAC of src_dpid's interface that connects to dst_dpid."""
        # Find the subnet connecting these two switches
        for subnet, info in self.switch_info.get(src_dpid, {}).items():
            for dst_subnet, dst_info in self.switch_info.get(dst_dpid, {}).items():
                if subnet == dst_subnet:
                    return info['mac']
        return None

    def _get_router_mac_for_ip(self, host_ip):
        """Finds the MAC of the router interface on the same subnet as the host."""
        
        # Create an IP address object for the host
        try:
            host_addr = ipaddress.ip_address(host_ip)
        except ValueError:
            self.logger.error("Invalid host IP address format: %s", host_ip)
            return None

        dpid = self.host_info[host_ip]['dpid']
        
        # Iterate through the subnets configured on the connected switch
        for subnet_cidr, info in self.switch_info.get(dpid, {}).items():
            try:
                # Create a network object from the CIDR string (e.g., "10.0.12.0/24")
                switch_subnet = ipaddress.ip_network(subnet_cidr)
                
                # Check if the host's IP address is contained within this subnet
                if host_addr in switch_subnet:
                    # If it is, we have found the correct router interface. Return its MAC.
                    return info['mac']
            except ValueError:
                self.logger.warning("Invalid subnet format in config: %s", subnet_cidr)
                continue # Try the next one
                
        return None

    def add_flow(self, datapath, priority, match, actions, idle_timeout=20, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)