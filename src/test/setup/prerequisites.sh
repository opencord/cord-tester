
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

function usage {
    echo "usage: ${0#*/} [-h |--help] [--cord] [--venv]"
    exit 1
}

on_cord=0
venv=0
optspec=":h-:"
while getopts "$optspec" optchar; do
    case "${optchar}" in
        -)
            case "${OPTARG}" in
                cord)
                    on_cord=1
                    ;;
                venv)
                    venv=1
                    ;;
                help)
                    usage
                    ;;
                *)
                    echo "Unknown option --${OPTARG}"
                    usage
                    ;;
            esac
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

shift $((OPTIND-1))
if [ $# -gt 0 ]; then
    usage
fi

apt-get update
release=$(lsb_release -cs)
#install docker only if not installed already. On cord, its mostly installed.
if $(which docker 2>&1 >/dev/null); then
    on_cord=1
else
    on_cord=0
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
    sleep 5
    echo "Verifying Docker installation"
    docker run --rm hello-world || exit 127
    docker rmi hello-world
    echo "Pulling ONOS latest"
    docker pull onosproject/onos:latest || exit 127
else
    echo "Skipping installation of Docker and ONOS"
fi

apt-get -y install openvswitch-common openvswitch-switch
apt-get -y install wget git python python-dev python-pip python-setuptools python-scapy python-pexpect python-maas-client tcpdump arping libssl-dev libffi-dev realpath python-virtualenv

setup_path=$(dirname $(realpath $0))
if [ $venv -eq 1 ]; then
    echo "Making a virtual cord-tester pip installation environment"
    mkdir -p $setup_path/venv
    virtualenv $setup_path/venv
    echo "Installing cord-tester pip packages on the virtual environment"
    $setup_path/venv/bin/pip install -r $setup_path/requirements.txt
else
    echo "Installing cord-tester pip packages on the host"
    pip install -r $setup_path/requirements.txt
fi

( cd /tmp && git clone https://github.com/jpetazzo/pipework.git && cp -v pipework/pipework /usr/bin && rm -rf pipework )

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

test_images=(cordtest/radius:candidate cordtest/quagga:candidate cordtest/nose:candidate)
for img in ${test_images[*]}; do
    echo "Pulling cord-tester image $img"
    docker pull $img 2>/dev/null
done
