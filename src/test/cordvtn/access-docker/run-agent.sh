#!/bin/bash

sudo docker run --privileged --cap-add=ALL -d --name access-agent -t ubuntu:14.04 /bin/bash
sudo ./pipework br-mgmt -i eth1 access 10.10.10.101/24
sudo ./pipework br-int -i eth2 access 10.168.0.101/24
