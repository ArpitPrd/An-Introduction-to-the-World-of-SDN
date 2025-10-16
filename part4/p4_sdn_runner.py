# File: p4_sdn_runner.py (Final Working Version with Explicit Ports)

import time
import json
import subprocess
import re
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# --- Plotting setup (no changes needed) ---
try:
    import matplotlib.pyplot as plt
    PLOT_ENABLED = True
except ImportError:
    info("Matplotlib not found. Plotting disabled.\n"); PLOT_ENABLED = False

def parse_iperf_log(file_path):
    times, throughputs = [], []
    pattern = re.compile(r'\[\s*\d+\]\s+\d+\.\d+-\s*(\d+\.\d+)\s+sec\s+.*\s+(\d+\.?\d*)\s+Mbits/sec')
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match: times.append(float(match.group(1))); throughputs.append(float(match.group(2)))
    except FileNotFoundError: info(f"Warning: iperf log file not found at {file_path}\n")
    return times, throughputs

def plot_throughput(log_file, title, filename):
    if not PLOT_ENABLED: return
    times, throughputs = parse_iperf_log(log_file)
    if not times: return
    plt.figure(figsize=(12, 6)); plt.plot(times, throughputs, marker='o', linestyle='-', color='blue')
    plt.title(title, fontsize=16); plt.xlabel("Time (seconds)", fontsize=12); plt.ylabel("Throughput (Mbits/sec)", fontsize=12)
    plt.grid(True); plt.xticks(range(0, int(max(times, default=0)) + 2, 2)); plt.ylim(bottom=0)
    plt.savefig(filename); info(f"*** Throughput plot saved to {filename} ***\n"); plt.close()

# --- Load configuration ---
with open('p4_config.json') as f: config = json.load(f)
H1_INFO, H2_INFO = config['hosts'][0], config['hosts'][1]
H1_IP, H1_MAC = f"{H1_INFO['ip']}/24", H1_INFO['mac']
H2_IP, H2_MAC = f"{H2_INFO['ip']}/24", H2_INFO['mac']

def build_sdn_topo():
    """Builds the Mininet topology with explicit port numbering to match the config."""
    net = Mininet(switch=OVSKernelSwitch, controller=None, link=TCLink, autoSetMacs=False)
    
    info('*** Adding remote controller\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    info('*** Adding switches\n')
    switches = {s['name']: net.addSwitch(s['name'], dpid=f"{s['dpid']:016x}") for s in config['switches']}
    
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip=H1_IP, mac=H1_MAC)
    h2 = net.addHost('h2', ip=H2_IP, mac=H2_MAC)

    # *** MODIFICATION: Explicitly set port numbers to match the JSON config ***
    info('*** Creating host links with explicit ports\n')
    h1_port = int(next(i['name'].split('-eth')[1] for s in config['switches'] for i in s['interfaces'] if s['name'] == 's1' and i['neighbor'] == 'h1'))
    h2_port = int(next(i['name'].split('-eth')[1] for s in config['switches'] for i in s['interfaces'] if s['name'] == 's6' and i['neighbor'] == 'h2'))
    net.addLink(h1, switches['s1'], port2=h1_port)
    net.addLink(h2, switches['s6'], port2=h2_port)

    info('*** Creating switch links with explicit ports\n')
    for link in config['links']:
        bw = 10 if ('s5' in link.values() and 's4' in link.values()) else 100
        src_name, dst_name = link['src'], link['dst']
        
        # Find the port numbers for each side of the link from the config file
        src_port = int(next(i['name'].split('-eth')[1] for s in config['switches'] for i in s['interfaces'] if s['name'] == src_name and i['neighbor'] == dst_name))
        dst_port = int(next(i['name'].split('-eth')[1] for s in config['switches'] for i in s['interfaces'] if s['name'] == dst_name and i['neighbor'] == src_name))
        
        net.addLink(switches[src_name], switches[dst_name], port1=src_port, port2=dst_port, bw=bw)
        
    net.build(); c0.start()
    for s in switches.values(): s.start([c0])
    
    info('*** Configuring host gateways and disabling IPv6\n')
    h1_gw = next(i['ip'] for s in config['switches'] for i in s['interfaces'] if s['name'] == 's1' and i['neighbor'] == 'h1')
    h2_gw = next(i['ip'] for s in config['switches'] for i in s['interfaces'] if s['name'] == 's6' and i['neighbor'] == 'h2')
    
    for h, gw in [(h1, h1_gw), (h2, h2_gw)]:
        h.cmd(f'ip route add default via {gw}')
        h.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        h.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        
    return net

def main():
    subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ryu_log = open("ryu_controller.log", "w")
    RYU_MANAGER_PATH = '/home/baadalvm/COL333_A3/ryu_py39_env/bin/ryu-manager'
    ryu_cmd = [RYU_MANAGER_PATH, '--verbose', 'p4_l3spf_lf.py']
    ryu_proc = subprocess.Popen(ryu_cmd, stdout=ryu_log, stderr=ryu_log)
    info(f'*** Started Ryu controller. Log at ryu_controller.log\n')
    info('*** Waiting 5s for Ryu controller to initialize...\n')
    time.sleep(5)
    
    net = build_sdn_topo()
    try:
        info("*** Waiting 5s for network to settle...\n")
        time.sleep(5)
        info('*** Ping: testing ping reachability\n'); 
        loss = net.pingAll()
        if loss > 0:
            info("--- !!! Ping test failed. Check ryu_controller.log for errors. !!! ---\n")
            return

        h1, h2 = net.get('h1', 'h2')
        info('*** Starting SDN Link Failure Experiment ***\n')
        iperf_time, down_duration, wait_before_down = 30, 5, 2
        ip = H2_IP.split('/')[0]
        c_log, s_log = "h1_iperf_sdn.log", "h2_iperf_sdn.log"
        h2.cmd("pkill -9 iperf || true"); time.sleep(0.5); h2.cmd(f"iperf -s > {s_log} 2>&1 &"); time.sleep(1)
        h1.cmd(f"iperf -c {ip} -t {iperf_time} -i 1 > {c_log} 2>&1 &")
        info(f"--- iperf running. Logs: {c_log}, {s_log}\n"); time.sleep(wait_before_down)
        info(f"--- DOWN s1 <-> s2 for {down_duration}s\n"); net.configLinkStatus('s1', 's2', 'down')
        time.sleep(down_duration)
        info(f"--- UP   s1 <-> s2\n"); net.configLinkStatus('s1', 's2', 'up')
        info("--- Flap done; waiting for iperf to finish...\n"); time.sleep(iperf_time)
        c_out, s_out = h1.cmd(f"cat {c_log}"), h2.cmd(f"cat {s_log}")
        print("\n==== iperf CLIENT (h1) SDN Link Failure Test ====\n" + c_out)
        print("\n==== iperf SERVER (h2) SDN Link Failure Test ====\n" + s_out)
        plot_throughput(c_log, "SDN Throughput During Link Failure", "sdn_throughput.png")
    finally:
        net.stop(); ryu_proc.terminate(); ryu_proc.wait(); ryu_log.close()
        subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    setLogLevel('info')
    main()