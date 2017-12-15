
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

# REST APIs for testing control plane functionalities in MCORD

#!/usr/bin/env python

SERVER_IP = 'c220g2-011013.wisc.cloudlab.us'
SERVER_PORT = '8080'
USER = 'xosadmin@opencord.org'
PASSWD = ''
EPC_INSTANCES = '/xosapi/v1/vepc/vepcserviceinstances'
CORE_INSTANCES = '/xosapi/v1/core/instances'
