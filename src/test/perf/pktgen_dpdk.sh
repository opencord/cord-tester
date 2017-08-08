
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


#!/bin/bash

#Get system info
name=`uname -n`

#Export env variables to inherit
export MY_DIR=$(pwd)
export DPDK_TAG=v16.11
export OVS_TAG=branch-2.7

#Clone repo and build DPDK
git clone http://dpdk.org/git/dpdk -b $DPDK_TAG $MY_DIR/dpdk
cd $MY_DIR/dpdk
export RTE_SDK=$(pwd)
export RTE_TARGET=x86_64-native-linuxapp-gcc
make -j4 install T=$RTE_TARGET

#Set for kernel mod
sudo apt-get install libpcap-dev
sudo apt-get install linux-headers-`uname -r`

#Hugepage allocation
sudo -E sysctl -w vm.nr_hugepages=1024
sudo -E umount /dev/hugepages
sudo -E mkdir -p /dev/hugepages
sudo -E mount -t hugetlbfs -o pagesize=2048k none /dev/hugepages

#Traffic generator powered by DPDK
wget http://fast.dpdk.org/rel/dpdk-16.11.1.tar.xz
wget http://dpdk.org/browse/apps/pktgen-dpdk/snapshot/pktgen-dpdk-pktgen-3.1.2.tar.gz
tar -xf dpdk-16.11.1.tar.xz
tar -xf pktgen-dpdk-pktgen-3.1.2.tar.gz

#Export env vars and make
export RTE_SDK=/home/ubuntu/dpdk-stable-16.11.1
export PKTGEN=/home/ubuntu/pktgen-dpdk-pktgen-3.1.2
export PKTGEN=/home/ubuntu/pktgen-dpdk-pktgen-3.1.2
export RTE_TARGET=x86_64-native-linuxapp-gcc
cd $RTE_SDK
make install T=x86_64-native-linuxapp-gcc
cd $PKTGEN
make

#Loads the UIO support module
if lsmod | grep "uio" &> /dev/null ; then
echo "uio module is loaded"
else
modprobe uio
fi

#Loading the the igb-uio.ko module
if lsmod | grep "igb_uio" &> /dev/null ; then
echo "igb_uio module is loaded"
else
insmod /dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
fi

iface=`python $RTE_SDK/tools/dpdk-devbind.py -s | awk '/ens4/ {print $1}'`
python $RTE_SDK/tools/dpdk-devbind.py -b igb_uio $iface

# RUN Pktgen
# -c COREMASK (0x3ff) (1111111111) 10 cores used with first core used for pktgen,
# -n Memory channels, -socket memory for each cpu, -m for memory allocation
# -P Promiscuous mode for all ports
./app/x86_64-native-linuxapp-gcc/pktgen -c 0x3ff -n 2 --proc-type auto --socket-mem 4096 -- -T -P -m "[2-5:6-9].0"
