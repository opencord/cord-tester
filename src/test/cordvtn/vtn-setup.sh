#!/bin/bash

sudo brctl addbr fabric
sudo ip link set fabric up
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo brctl addif fabric veth0
sudo brctl addif fabric eth1
sudo ip addr flush eth1
sudo ip link set address 00:00:00:00:00:01 dev fabric
sudo ip link set address 00:00:00:00:00:01 dev eth1
sudo ip address add 20.0.0.1/24 dev fabric
sudo ip address add 10.168.0.1/24 dev fabric
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
