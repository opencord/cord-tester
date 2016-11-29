#!/bin/bash

sudo docker run --privileged --cap-add=ALL -d -v /dev:/dev -v /lib/modules:/lib/modules --name access -t vlan /bin/bash
sudo ./pipework fabric -i eth1 access 10.168.0.254/24
sudo docker exec -d access modprobe 8021q
sudo docker exec -d access vconfig add eth1 222
sudo docker exec -d access ip link set eth1.222 up
sudo docker exec -d access ip addr add 10.169.0.254/24 dev eth1.222
