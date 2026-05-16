#!/bin/bash
# cleanup_snort_mirror.sh

sudo ovs-vsctl clear Bridge s1 mirrors
sudo ovs-vsctl del-port s1 s1-snort 2>/dev/null
sudo ip link del s1-snort 2>/dev/null
sudo mn -c
