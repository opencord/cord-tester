
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
odir="$1"
if [ -z "$odir" ]; then
    odir = "./"
fi

##Generate TLS authentication Test state machine
python yamlFsm.py -p TlsAuthHolder -f noseTlsAuthTest.yaml > ${odir}/noseTlsAuthHolder.py

##Generate PAP authentication state machine
python yamlFsm.py -p PAPAuthHolder -f nosePAPTest.yaml > ${odir}/nosePAPAuthHolder.py


##Generate DNS test state machine
#python yamlFsm.py -p DnsHolder -f noseDnsTest.yaml > ${odir}/noseDnsHolder.py

#Generate EAP MD5 authentication state machine
python yamlFsm.py -p Md5AuthHolder -f noseMD5AuthTest.yaml > ${odir}/noseMd5AuthHolder.py


