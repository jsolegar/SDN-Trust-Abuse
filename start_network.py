# -*- coding: utf-8 -*-
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
from SDNTrustTopo import SDNTrustTopo
import time
import os

ADMIN_IP = '10.0.0.100'
H2_IP = '10.0.0.20'
H3_IP = '10.0.0.30'

def start_services(net):
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')
    admin = net.get('admin')

    print("=== [1/9] Levantando proxy en h2 ===")
    h2.cmd('python3 /home/sds/SDS_Project/proxy_h2.py > /tmp/proxy_h2.log 2>&1 &')

    print("=== [2/9] Levantando backend en h3 ===")
    h3.cmd('python3 -m http.server 80 > /tmp/h3_server.log 2>&1 &')

    print("=== [3/9] Levantando SSH en h2 ===")
    h2.cmd('/usr/sbin/sshd -D &')

    print("=== [4/9] Copiando proxy_h2.py al home de sdsh2 ===")
    h2.cmd('cp /home/sds/SDS_Project/proxy_h2.py /home/sdsh2/')
    h2.cmd('chown sdsh2:sdsh2 /home/sdsh2/proxy_h2.py')

    print("=== [5/9] Levantando servicios en decoys ===")
    # H4 - Mail server (puerto 25)
    h4.cmd('python3 -m http.server 25 > /tmp/h4_server.log 2>&1 &')
    # H5 - FTP server (puerto 21)
    h5.cmd('python3 -m http.server 21 > /tmp/h5_server.log 2>&1 &')
    # H6 - DNS server (puerto 53)
    h6.cmd('python3 -m http.server 53 > /tmp/h6_server.log 2>&1 &')

    print("=== [6/9] Configurando firewall en h2 ===")
    h2.cmd('iptables -A INPUT -p tcp --dport 80 -j ACCEPT')
    h2.cmd('iptables -A INPUT -p tcp --dport 22 -j ACCEPT')
    h2.cmd('iptables -A INPUT -p icmp -j ACCEPT')
    h2.cmd('iptables -A INPUT -p tcp -j DROP')

    print("=== [7/9] Configurando firewall en h3 ===")
    h3.cmd('iptables -A INPUT -s ' + H2_IP + ' -j ACCEPT')
    h3.cmd('iptables -A INPUT -j DROP')

    print("=== [8/9] Configurando firewall en decoys ===")
    h4.cmd('iptables -A INPUT -p tcp --dport 25 -j ACCEPT')
    h4.cmd('iptables -A INPUT -p icmp -j ACCEPT')
    h4.cmd('iptables -A INPUT -p tcp -j DROP')

    h5.cmd('iptables -A INPUT -p tcp --dport 21 -j ACCEPT')
    h5.cmd('iptables -A INPUT -p icmp -j ACCEPT')
    h5.cmd('iptables -A INPUT -p tcp -j DROP')

    h6.cmd('iptables -A INPUT -p tcp --dport 53 -j ACCEPT')
    h6.cmd('iptables -A INPUT -p icmp -j ACCEPT')
    h6.cmd('iptables -A INPUT -p tcp -j DROP')

    print("=== [9/9] Configurando firewall en admin ===")
    admin.cmd('iptables -A INPUT -p tcp -j DROP')

    print("===================================================")
    print("*** Servicios levantados:")
    print("*** h2    -> Proxy HTTP (80) + SSH (22) misconfigured")
    print("*** h3    -> Backend HTTP (80) solo desde h2")
    print("*** h4    -> Mail server (25)")
    print("*** h5    -> FTP server (21)")
    print("*** h6    -> DNS server (53)")
    print("*** admin -> Trusted admin (10.0.0.100)")
    print("===================================================")

def setup_snort_mirror():
    print("=== Configurando s1-snort mirror ===")
    os.system('ip link add name s1-snort type dummy')
    os.system('ip link set s1-snort up')
    os.system('ovs-vsctl add-port s1 s1-snort')
    os.system('ovs-vsctl -- set Bridge s1 mirrors=@m \
        -- --id=@s1-snort get Port s1-snort \
        -- --id=@m create Mirror name=snort-mirror \
        select-all=true \
        output-port=@s1-snort')
    print("=== Mirror configurado ===")

def cleanup_snort_mirror():
    print("=== Limpiando s1-snort mirror ===")
    os.system('ovs-vsctl clear Bridge s1 mirrors')
    os.system('ovs-vsctl del-port s1 s1-snort')
    os.system('ip link del s1-snort')
    print("=== Limpieza completa ===")

if __name__ == '__main__':
    setLogLevel('info')

    topo = SDNTrustTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False
    )

    net.start()
    time.sleep(2)

    setup_snort_mirror()
    start_services(net)

    print("=================================================")
    print("*** Red lista. Lanza Snort en otra terminal:")
    print("*** sudo snort -i s1-snort -A unsock -N -l /tmp -c /etc/snort/snort.conf")
    print("=================================================")

    CLI(net)

    cleanup_snort_mirror()
    net.stop()
