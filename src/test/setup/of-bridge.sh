#!/usr/bin/env bash
bridge="$1"
controller="$2"
if [ x"$bridge" = "x" ]; then
  bridge="ovsbr0"
fi
if [ x"$controller" = "x" ]; then
  controller="$ONOS_CONTROLLER_IP"
fi
pkill -9 ofdatapath
pkill -9 ofprotocol
service openvswitch-switch restart
num_ports=200
ports=$(($num_ports-1))
for vports in $(seq 0 2 $ports); do
   echo "Deleting veth$vports"
   ip link del veth$vports 2>/dev/null
done
for vports in $(seq 0 2 $ports); do
  ip link add type veth
  ifconfig veth$vports up
  ifconfig veth$(($vports+1)) up
done
echo "Configuring ovs bridge $bridge"
ovs-vsctl del-br $bridge
ovs-vsctl add-br $bridge
#ovs-vsctl set bridge $bridge other-config:hwaddr=00:11:22:33:44:55
for i in $(seq 1 2 $ports); do
  ovs-vsctl add-port $bridge veth$i
done
ctlr=""
for ip in `echo $controller | tr ',' '\n'`; do
  ctlr="$ctlr tcp:$ip:6653"
done
ovs-vsctl set-controller $bridge $ctlr
ovs-vsctl set controller $bridge max_backoff=1000
ovs-vsctl set bridge $bridge protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ovs-vsctl show
ovs-ofctl show $bridge
