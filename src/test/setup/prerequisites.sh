#!/usr/bin/env bash
apt-get update
apt-get -y install apt-transport-https ca-certificates
apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
    echo deb https://apt.dockerproject.org/repo ubuntu-trusty main |  tee /etc/apt/sources.list.d/docker.list
fi
apt-get update
apt-get purge lxc-docker || true
apt-get -y install linux-image-extra-$(uname -r)
apt-get -y install apparmor
echo "Installing Docker"
apt-get -y install docker-engine
service docker start
echo "Verifying Docker installation"
docker run hello-world || exit 127
echo "Pulling ONOS latest and 1.5"
docker pull onosproject/onos:latest || exit 127
docker pull onosproject/onos:1.5 || exit 127
apt-get -y install wget git python python-dev python-pip python-setuptools python-scapy tcpdump arping
easy_install nose
apt-get -y install openvswitch-common openvswitch-switch
pip install -U scapy
pip install monotonic
pip install configObj
pip install -U docker-py
pip install -U pyyaml
pip install -U nsenter
pip install -U pyroute2
pip install -U netaddr
pip install scapy-ssl_tls
## Special mode to pull cord-tester repo in case prereqs was installed by hand instead of repo
if [ "$1" = "-test" ]; then
    rm -rf cord-tester
    git clone https://github.cyanoptics.com/cgaonker/cord-tester.git
fi