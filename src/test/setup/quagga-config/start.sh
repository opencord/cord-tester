#!/bin/bash
ulimit -n 65536
ip a add 10.10.0.3/16 dev eth1
#bgpd -u root -f /root/config/bgpd.conf &
conf_file=${1:-/root/config/testrib.conf}
base_conf=$(basename $conf_file)
base_conf=${base_conf%%.conf}
if [[ $base_conf == bgpd* ]]; then
    /usr/local/sbin/bgpd -u root -f $conf_file
else
    /usr/local/sbin/zebra -u root -f $conf_file
fi
