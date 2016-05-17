#!/usr/bin/env bash
dpid=${1:-001122334455}
num_ports=${2:-200}
controller=${3:-$ONOS_CONTROLLER_IP}
num_ports=$(($num_ports-1))
my_ip=`ifconfig eth0 | grep "inet addr" | tr -s ' ' | cut -d":" -f2 |cut -d" " -f1`
if_list="veth1"
for port in $(seq 3 2 $num_ports); do
    if_list="$if_list"",""veth$port"
done
service openvswitch-switch stop
nohup ofdatapath --no-slicing --datapath-id=$dpid --interfaces=$if_list ptcp:6653 2>&1 >/tmp/nohup.out &
nohup ofprotocol tcp:$my_ip:6653 tcp:$controller:6633 2>&1 >/tmp/nohup.out &
