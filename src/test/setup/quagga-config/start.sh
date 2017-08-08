
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
ulimit -n 65536
ip a add 10.10.0.3/16 dev eth1
#bgpd -u root -f /root/config/bgpd.conf &
conf_file=${1:-/root/config/testrib.conf}
base_conf=$(basename $conf_file)
base_conf=${base_conf%%.conf}
if [[ $base_conf == bgpd* ]]; then
    /usr/local/sbin/bgpd -u root -f $conf_file
else
    /usr/local/sbin/zebra -u root -f $conf_file
fi
