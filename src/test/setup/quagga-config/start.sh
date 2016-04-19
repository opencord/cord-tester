#!/bin/bash
ulimit -n 65536
ip a add 10.10.0.3/16 dev eth1
#bgpd -u root -f /root/config/bgpd.conf &
/usr/local/sbin/zebra -u root -f /root/config/testrib.conf
