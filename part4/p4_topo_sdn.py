from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def build_sdn():
    net = Mininet(
        controller=None, build=False, link=TCLink,
        switch=OVSSwitch, autoSetMacs=True, autoStaticArp=True
    )
    
    info('*** Adding controller\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001')
    s2 = net.addSwitch('s2', dpid='0000000000000002')
    s3 = net.addSwitch('s3', dpid='0000000000000003')
    s4 = net.addSwitch('s4', dpid='0000000000000004')
    s5 = net.addSwitch('s5', dpid='0000000000000005')
    s6 = net.addSwitch('s6', dpid='0000000000000006')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.12.2/24', mac='00:00:00:00:01:02')
    h2 = net.addHost('h2', ip='10.0.67.2/24', mac='00:00:00:00:06:02')

    info('*** Creating links with specified bandwidths\n')
    net.addLink(h1, s1)
    net.addLink(h2, s6)

    # Primary Path (s1-s2-s3-s6) - Bottleneck is 10Mbps
    net.addLink(s1, s2, bw=10) # Link to be failed
    net.addLink(s2, s3, bw=100) 
    net.addLink(s3, s6, bw=10)

    # Alternate Path (s1-s4-s5-s6) - Bottleneck is 100Mbps
    net.addLink(s1, s4, bw=100)
    net.addLink(s4, s5, bw=100)
    net.addLink(s5, s6, bw=100)
    
    # Set host default routes
    h1.cmd('ip route add default via 10.0.12.1')
    h2.cmd('ip route add default via 10.0.67.1')

    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = build_sdn()
    net.start()
    CLI(net)
    net.stop()