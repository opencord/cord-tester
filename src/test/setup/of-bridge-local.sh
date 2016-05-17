#!/usr/bin/env bash
bridge="$1"
controller="$2"
if [ x"$bridge" = "x" ]; then
  bridge="ovsbr0"
fi
if [ x"$controller" = "x" ]; then
  controller=$ONOS_CONTROLLER_IP
fi
pkill -9 ofdatapath
pkill -9 ofprotocol
service openvswitch-switch start
echo "Configuring ovs bridge $bridge"
ovs-vsctl del-br $bridge
ovs-vsctl add-br $bridge
my_ip=`ifconfig docker0 | grep "inet addr" | tr -s ' ' | cut -d":" -f2 |cut -d" " -f1`
ovs-vsctl set-controller $bridge ptcp:6653:$my_ip tcp:$controller:6633
ovs-vsctl set controller $bridge max_backoff=1000
ovs-vsctl set bridge $bridge protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ovs-vsctl show
ovs-ofctl show $bridge
