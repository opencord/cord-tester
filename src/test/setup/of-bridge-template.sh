#!/usr/bin/env bash
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


bridge="$1"
controller="$2"
if [ x"$bridge" = "x" ]; then
  bridge="br0"
fi
if [ x"$controller" = "x" ]; then
  controller="%%CONTROLLER%%"
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
