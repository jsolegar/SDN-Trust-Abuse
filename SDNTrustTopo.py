# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.link import TCLink

class SDNTrustTopo(Topo):
    def __init__(self):
        print("===================================================")
        print("Creating SDN Trust Abuse topology...")
        print("===================================================")
        Topo.__init__(self)

        # =================================================
        # Hosts
        # =================================================
        print("*** Adding attacker host h1")
        h1 = self.addHost('h1', ip='10.0.0.10/24')

        print("*** Adding frontend web server h2")
        h2 = self.addHost('h2', ip='10.0.0.20/24')

        print("*** Adding critical backend h3")
        h3 = self.addHost('h3', ip='10.0.0.30/24')

        print("*** Adding DMZ decoy servers h4/h5/h6")
        h4 = self.addHost('h4', ip='10.0.0.40/24')
        h5 = self.addHost('h5', ip='10.0.0.50/24')
        h6 = self.addHost('h6', ip='10.0.0.60/24')

        print("*** Adding trusted admin host")
        admin = self.addHost('admin', ip='10.0.0.100/24')

        # =================================================
        # Switch
        # =================================================
        print("*** Adding OpenFlow switch s1")
        s1 = self.addSwitch('s1')

        # =================================================
        # Links
        # =================================================
        print("*** Creating network links")
        self.addLink(h1, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(h2, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(h3, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(h4, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(h5, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(h6, s1, cls=TCLink, bw=10, max_queue_size=500)
        self.addLink(admin, s1, cls=TCLink, bw=10, max_queue_size=500)

        print("===================================================")
        print("*** Host roles:")
        print("*** h1    -> External attacker      (10.0.0.10)")
        print("*** h2    -> Frontend web server    (10.0.0.20)")
        print("*** h3    -> Critical backend       (10.0.0.30)")
        print("*** h4    -> DMZ decoy server       (10.0.0.40)")
        print("*** h5    -> DMZ decoy server       (10.0.0.50)")
        print("*** h6    -> DMZ decoy server       (10.0.0.60)")
        print("*** admin -> Trusted admin host     (10.0.0.100)")
        print("*** s1-snort -> OVS mirror          (externo)")
        print("===================================================")

topos = {
    'sdntrust': (lambda: SDNTrustTopo())
}
