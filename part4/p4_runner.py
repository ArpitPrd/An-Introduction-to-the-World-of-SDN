#!/usr/bin/env python3
# main.py — orchestrates: build topo -> start FRR/OSPF -> warm-up -> flap & iperf -> plot -> (optional CLI)

import argparse, json, time, re
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from p4_topo import build, H1_IP, H2_IP
from p4_ospf import start_frr_ospf, wait_for_convergence, stop_frr, generate_meta_ospf

try:
    import matplotlib.pyplot as plt
    PLOT_ENABLED = True
except ImportError:
    info("Matplotlib not found. Plotting disabled. Install with: pip install matplotlib\n")
    PLOT_ENABLED = False

def parse_iperf_log(file_path):
    """Parses an iperf log to extract time and throughput for plotting."""
    times, throughputs = [], []
    pattern = re.compile(r'\[\s*\d+\]\s+\d+\.\d+-\s*(\d+\.\d+)\s+sec\s+.*\s+(\d+\.?\d*)\s+Mbits/sec')
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    times.append(float(match.group(1)))
                    throughputs.append(float(match.group(2)))
    except FileNotFoundError:
        info(f"Warning: iperf log file not found at {file_path}\n")
    return times, throughputs

def plot_throughput(log_file, title, filename):
    """Generates and saves a throughput plot from an iperf log file."""
    if not PLOT_ENABLED: return
    times, throughputs = parse_iperf_log(log_file)
    if not times: return
    
    plt.figure(figsize=(12, 6))
    plt.plot(times, throughputs, marker='o', linestyle='-', color='blue')
    plt.title(title, fontsize=16)
    plt.xlabel("Time (seconds)", fontsize=12)
    plt.ylabel("Throughput (Mbits/sec)", fontsize=12)
    plt.grid(True)
    plt.xticks(range(0, int(max(times, default=0)) + 2, 2))
    plt.ylim(bottom=0)
    plt.savefig(filename)
    info(f"*** Throughput plot saved to {filename} ***\n")
    plt.close()

def if_down_up(net, edge, down=True):
    """Bring both sides of a router-router link down/up."""
    ri, rj = net.get(edge["s_i"]), net.get(edge["s_j"])
    ifs = (edge["i_if"], edge["j_if"])
    action = "down" if down else "up"
    ri.cmd(f"ip link set {ifs[0]} {action}")
    rj.cmd(f"ip link set {ifs[1]} {action}")

def start_iperf(h1, h2, h1_ip, h2_ip, total_seconds, log_prefix=""):
    """Start server on h2, client on h1. Returns (server_log, client_log)."""
    s_log = f"h2_iperf_{log_prefix}.log"
    c_log = f"h1_iperf_{log_prefix}.log"
    ip = h2_ip.split("/")[0]
    
    h2.cmd("pkill -9 iperf || true")
    time.sleep(0.5)
    
    h2.cmd(f"iperf -s > {s_log} 2>&1 &")
    time.sleep(0.5)
    h1.cmd(f"iperf -c {ip} -t {int(total_seconds)} -i 1 > {c_log} 2>&1 &")
    return s_log, c_log

def run_warmup_exp(net, meta_ospf):
    info('*** 1. Running OSPF Warm-up Experiment ***\n')
    h1, h2 = net.get("h1"), net.get("h2")
    s1, s6 = net.get("s1"), net.get(meta_ospf["routers"][-1])
    
    s_log, c_log = start_iperf(h1, h2, H1_IP, H2_IP, 10, log_prefix="warmup")
    info(f"--- Warm-up iperf running for 10s. Logs: {c_log}, {s_log}\n")
    time.sleep(12) # Wait for iperf to finish
    
    c_out = h1.cmd(f"cat {c_log}")
    s_out = h2.cmd(f"cat {s_log}")
    
    print("\n==== iperf CLIENT (h1) Warm-up ====\n" + c_out)
    print("\n==== iperf SERVER (h2) Warm-up ====\n" + s_out)
    
    info('--- Recording forwarding rules on s1 and s6:\n')
    route_s1 = s1.cmd(f'vtysh -c "show ip route ospf"')
    route_s6 = s6.cmd(f'vtysh -c "show ip route ospf"')
    print("\n==== s1 OSPF Routing Table ====\n" + route_s1)
    print("\n==== s6 OSPF Routing Table ====\n" + route_s6)
    info('*** Warm-up Experiment Complete ***\n')

def link_flap_exp(net, e, h1_ip, h2_ip, iperf_time=30, link_down_duration=5, wait_before_link_down=2):
    """Choose distinct edges and flap them in sequence."""
    h1, h2 = net.get("h1"), net.get("h2")
    s1 = net.get("s1") # Get a handle to router s1

    # --- ADD THIS SECTION to start capturing OSPF packets ---
    info("*** Starting tcpdump on s1 to capture OSPF control packets (proto 89)\n")
    s1.cmd("tcpdump -i any -n proto 89 -w s1_ospf.pcap &")
    # --- END ADDITION ---

    s_log, c_log = start_iperf(h1, h2, h1_ip, h2_ip, iperf_time, log_prefix="flap")
    
    info(f"*** iperf running: client log {c_log}, server log {s_log}\n")
    
    time.sleep(wait_before_link_down)
    
    info(f"DOWN {e['s_i']}:{e['i_if']} <-> {e['s_j']}:{e['j_if']} for {link_down_duration}s\n")
    if_down_up(net, e, down=True)
    time.sleep(link_down_duration)
    info(f"UP   {e['s_i']}:{e['i_if']} <-> {e['s_j']}:{e['j_if']}\n")
    if_down_up(net, e, down=False)
    
    info("*** Flaps done; waiting for iperf to finish...\n")
    time.sleep(iperf_time - link_down_duration - wait_before_link_down + 5)
    
    # --- ADD THIS LINE to stop the packet capture ---
    s1.cmd("pkill -9 tcpdump")
    # --- END ADDITION ---

    c_out = h1.cmd(f"tail -n +1 {c_log} || true")
    s_out = h2.cmd(f"tail -n +1 {s_log} || true")
    
    plot_throughput(c_log, "OSPF Throughput During Link Failure", "ospf_throughput.png")
    
    return c_out, s_out

def main():
    ap = argparse.ArgumentParser(description="Mininet + FRR OSPF with link flaps and iperf.")
    ap.add_argument("--input-file", required=True, help="config json for OSPF")
    ap.add_argument("--converge-timeout", type=int, default=60, help="Seconds to wait for initial convergence")
    ap.add_argument("--no-cli", action="store_true", help="Exit after test (no Mininet CLI)")
    args = ap.parse_args()

    with open(args.input_file) as f:
        config = json.load(f)

    net = build()
    meta_ospf = generate_meta_ospf(config)
    try:
        start_frr_ospf(net, meta_ospf)

        info(f"*** Waiting for OSPF convergence (<= {args.converge_timeout}s)...\n")
        if wait_for_convergence(net, meta_ospf, timeout=args.converge_timeout):
            info("✅ OSPF converged (routes present)\n")
        else:
            info("⚠️  OSPF did not converge within timeout.\n")

        run_warmup_exp(net, meta_ospf)

        info('*** 2. Starting OSPF Link Failure Experiment ***\n')
        flap_edge = next((x for x in meta_ospf["edges"] if x["s_i"] == "s1" and x["s_j"] == "s2"), None)
        c_out, s_out = link_flap_exp(net, flap_edge, h1_ip=H1_IP, h2_ip=H2_IP)

        print("\n==== iperf CLIENT (h1) Link Failure Test ====\n" + c_out)
        print("\n==== iperf SERVER (h2) Link Failure Test ====\n" + s_out)

        if not args.no_cli:
            print("\n*** Examples:")
            print("  s1 ip route")
            print("  s2 vtysh -c 'show ip ospf neighbor'")
            print("  h1 ping -c 3 h2")
            CLI(net)
            
    finally:
        stop_frr(net, meta_ospf)
        net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    main()