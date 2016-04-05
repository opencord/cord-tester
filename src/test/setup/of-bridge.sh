#!/usr/bin/env bash
bridge="$1"
controller="$2"
if [ x"$bridge" = "x" ]; then
  bridge="br0"
fi
if [ x"$controller" = "x" ]; then
  controller=$ONOS_CONTROLLER_IP
fi
service openvswitch-switch restart
num_ports=200
ports=$(($num_ports-1))
for vports in $(seq 0 2 $ports); do
   echo "Deleting veth$vports"
   ip link del veth$vports
done
for vports in $(seq 0 2 $ports); do
  ip link add type veth
  ifconfig veth$vports up
  ifconfig veth$(($vports+1)) up
done
echo "Configuring ovs bridge $bridge"
ovs-vsctl del-br $bridge
ovs-vsctl add-br $bridge
for i in $(seq 1 2 $ports); do
  ovs-vsctl add-port $bridge veth$i
done
my_ip=`ifconfig eth0 | grep "inet addr" | tr -s ' ' | cut -d":" -f2 |cut -d" " -f1`
ovs-vsctl set-controller $bridge ptcp:6653:$my_ip tcp:$controller:6633
ovs-vsctl set controller $bridge max_backoff=1000
ovs-vsctl set bridge $bridge protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ovs-vsctl show
ovs-ofctl show $bridge
