#!/usr/bin/env bash
bridge="$1"
controller="$2"
voltha_loc="$3"
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

#Delete existing bridges if any
for br in "${bridges[@]}"; do
    ovs-vsctl del-br $br
done

proto=tcp
if [ x"$voltha_loc" != "x" ]; then
    onos_jks="$voltha_loc/docker/onos_cfg/onos.jks"
    client_cert="$voltha_loc/pki/voltha.crt"
    if [ -f $onos_jks ]; then
        #extract server certificate
        keytool -export -alias onos -file /tmp/onos.der -keystore $onos_jks -storepass 222222
        openssl x509 -inform der -in /tmp/onos.der -out /tmp/onos-cert.pem
        cat /tmp/onos-cert.pem $client_cert > /tmp/voltha-CA.pem
        echo "Enabling OVS SSL connection to controller"
        ovs-vsctl set-ssl $voltha_loc/pki/voltha.key $client_cert /tmp/voltha-CA.pem
        proto=ssl
    fi
fi

ctlr=""
for ip in `echo $controller | tr ',' '\n'`; do
  ctlr="$ctlr $proto:$ip:6653"
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
