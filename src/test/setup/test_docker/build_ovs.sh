#!/usr/bin/env bash
echo "OVS installation"
cd /root/ && tar zxpvf openvswitch-2.4.0.tar.gz -C /root/ovs
cd /root/ovs
cd openvswitch-2.4.0 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && make && make install
service openvswitch-controller stop
service openvswitch-switch restart
