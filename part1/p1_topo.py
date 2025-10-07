from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.clean import cleanup

class CustomTopo(Topo):
    """
    Custom topology for Part 1: 2 switches, 4 hosts.
    h1, h2 --- s1 --- s2 --- h3, h4
    """
    def build(self):
        # Add two switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Connect hosts to switch S1
        self.addLink(h1, s1)
        self.addLink(h2, s1)

        # Connect hosts to switch S2
        self.addLink(h3, s2)
        self.addLink(h4, s2)

        # Connect the two switches
        self.addLink(s1, s2)

def run():
    """Create and start the network."""
    topo = CustomTopo()

    # Create the network and specify the external controller.
    # This configuration prevents Mininet from starting its own internal controller.
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=RemoteController, # Use the RemoteController class
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=False) # build=False is good practice before starting

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    # It's good practice to clean up previous Mininet runs before starting
    cleanup()
    setLogLevel('info')
    run()

