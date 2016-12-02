#!/usr/bin/env bash
apt-get update
on_cord=0
release=$(lsb_release -cs)
if [ "$1" = "--cord" ]; then
    echo "Skipping installation of Docker and ONOS"
    on_cord=1
fi
if [ $on_cord -eq 0 ]; then
    apt-get -y install apt-transport-https ca-certificates
    apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
    if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
        echo deb https://apt.dockerproject.org/repo ubuntu-$release main |  tee /etc/apt/sources.list.d/docker.list
    fi
    apt-get update
    apt-get purge lxc-docker || true
    apt-get -y install linux-image-extra-$(uname -r)
    apt-get -y install apparmor
    echo "Installing Docker"
    apt-get -y install docker-engine
    service docker restart
    echo "Verifying Docker installation"
    docker run --rm hello-world || exit 127
    docker rmi hello-world
    echo "Pulling ONOS latest"
    docker pull onosproject/onos:latest || exit 127
    apt-get -y install openvswitch-common openvswitch-switch
fi
apt-get -y install wget git python python-dev python-pip python-setuptools python-scapy python-pexpect python-maas-client tcpdump arping libssl-dev
easy_install nose
pip install scapy==2.3.2
pip install monotonic
pip install configObj
pip install docker-py==1.9.0
pip install -U pyyaml
pip install -U nsenter
pip install -U pyroute2
pip install -U netaddr
pip install -U python-daemon
pip install scapy-ssl_tls==1.2.2
pip install -U robotframework
pip install -U robotframework-requests
pip install -U robotframework-sshlibrary
pip install paramiko==1.10.1
( cd /tmp && git clone https://github.com/jpetazzo/pipework.git && cp -v pipework/pipework /usr/bin && rm -rf pipework )

## Special mode to pull cord-tester repo in case prereqs was installed by hand instead of repo
if [ "$1" = "--test" ]; then
    rm -rf cord-tester
    git clone https://github.com/opencord/cord-tester.git
fi

install_ovs() {
    mkdir -p /root/ovs
    wget http://openvswitch.org/releases/openvswitch-2.5.0.tar.gz -O /root/ovs/openvswitch-2.5.0.tar.gz && \
    ( cd /root/ovs && tar zxpvf openvswitch-2.5.0.tar.gz && \
      cd openvswitch-2.5.0 && \
      ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && make && make install
    )
}

ovs_install=0

if [ -f /usr/bin/ovs-vsctl ] || [ -f /usr/local/bin/ovs-vsctl ]; then
    ##find the version. Install if ovs version less than 2.5
    version=`sudo ovs-vsctl --version | head -1  | awk '/[1-9].[0-9].[0-9]/ {print $NF}'`
    major=$(echo $version | cut -d "." -f1)
    minor=$(echo $version | cut -d "." -f2)
    if [ $major -le 2 ]; then
        if [ $major -lt 2 ]; then
            ovs_install=1
        else
            if [ $minor -lt 5 ]; then
                ovs_install=1
            fi
        fi
    fi
else
    ovs_install=1
fi

if [ $ovs_install -eq 1 ]; then
    echo "Installing OVS 2.5.0"
    service openvswitch-switch stop
    install_ovs
fi
