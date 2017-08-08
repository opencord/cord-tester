
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
bridges=()
num_bridges=1
if [[ $bridge =~ ^[0-9]+$ ]]; then
    num_bridges=$bridge
    if [ $num_bridges -eq 0 ]; then
        num_bridges=1
    fi
    for num in $(seq $num_bridges); do
        if [ $num -eq 1 ]; then
            br=br-int
        else
            br=br-int$num
        fi
        n=$(($num-1))
        bridges[$n]=$br
    done
else
    bridges[0]=$bridge
fi

ctlr=""
for ip in `echo $controller | tr ',' '\n'`; do
  ctlr="$ctlr tcp:$ip:6653"
done

#Delete existing bridges if any
for br in "${bridges[@]}"; do
    ovs-vsctl del-br $br
done

for br in "${bridges[@]}"; do
    echo "Configuring OVS bridge:$br"
    ovs-vsctl add-br $br
    ovs-vsctl set-controller $br $ctlr
    ovs-vsctl set controller $br max_backoff=1000
    ovs-vsctl set bridge $br protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
done

for br in "${bridges[@]}"; do
    ovs-vsctl show
    ovs-ofctl show $br
done
