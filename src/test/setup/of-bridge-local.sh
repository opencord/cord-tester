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
echo "Configuring ovs bridge $bridge"
ovs-vsctl del-br $bridge
ovs-vsctl add-br $bridge
ctlr=""
for ip in `echo $controller | tr ',' '\n'`; do
  ctlr="$ctlr tcp:$ip:6653"
done
ovs-vsctl set-controller $bridge $ctlr
ovs-vsctl set controller $bridge max_backoff=1000
ovs-vsctl set bridge $bridge protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ovs-vsctl show
ovs-ofctl show $bridge
