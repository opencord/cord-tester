
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


#!/usr/bin/env python

SERVER_IP = ''
SERVER_PORT = '30006'
XOS_USER = 'admin@opencord.org'
XOS_PASSWD = ''
VOLT_SUBSCRIBER = '/xosapi/v1/rcord/rcordsubscribers'
VOLT_TENANT = '/xosapi/v1/volt/voltserviceinstances'
VOLT_DEVICE = '/xosapi/v1/volt/oltdevices'
ONU_DEVICE = '/xosapi/v1/volt/onudevices'
VOLT_SERVICE = '/xosapi/v1/volt/voltservices'
PON_PORT = '/xosapi/v1/volt/ponports'
CH_CORE_SERVICELINK = '/xosapi/v1/core/serviceinstancelinks'
TENANT_SUBSCRIBER = '/api/tenant/cord/subscriber/'
TENANT_VOLT = '/api/tenant/cord/volt/'
UTILS_SYNCHRONIZER = '/api/utility/synchronizer/'
UTILS_LOGIN = '/api/utility/login/'
CORE_USERS = '/api/core/users/'
CH_CORE_USERS = '/xosapi/v1/core/users'
CORE_SERVICES = '/api/core/services/'
CH_CORE_SERVICES = '/xosapi/v1/core/services'
CORE_INSTANCES = '/api/core/instances/'
CH_CORE_INSTANCES = '/xosapi/v1/core/instances'
CORE_DEPLOYMENTS = '/api/core/deployments/'
CH_CORE_DEPLOYMENTS = '/xosapi/v1/core/deployments'
CORE_SANITY_INSTANCES = '/api/core/instances/?no_hyperlinks=1'
CORE_SANITY_SLICES = '/api/core/slices/?no_hyperlinks=1'
CORE_SLICES = '/api/core/slices/'
CH_CORE_SLICES = '/xosapi/v1/core/slices'
CORE_SANITY_NODES = '/api/core/nodes/?no_hyperlinks=1'
CORE_NODES = '/api/core/nodes/'
CH_CORE_NODES = '/xosapi/v1/core/nodes'
CORE_FLAVORS = '/api/core/flavors/'
CH_CORE_FLAVORS = '/xosapi/v1/core/flavors'
CORE_SITES = '/api/core/sites/'
CH_CORE_SITES = '/xosapi/v1/core/sites'
CORE_IMAGES = '/api/core/images/'
CH_CORE_IMAGES = '/xosapi/v1/core/images'
CORE_SITEDEPLOYMENTS = '/api/core/sitedeployments'
CH_CORE_NETWORKS = '/xosapi/v1/core/networks'
CH_CORE_SLICES = '/xosapi/v1/core/slices'
CH_CORE_NETWORK_SLICES = '/xosapi/v1/core/networkslices'
CH_CORE_PORTS = '/xosapi/v1/core/ports'
CH_CORE_SERVICES = '/xosapi/v1/core/services'
CH_CORE_SITEDEPLOYMENTS = '/xosapi/v1/core/sitedeployments'
CH_CORE_NETWORK_TEMPLATES = '/xosapi/v1/core/networktemplates'
VSG_TENANT = '/xosapi/v1/vsg/vsgserviceinstances'
HWVSG_TENANT = '/xosapi/v1/vsg-hw/vsghwserviceinstances'
FABRIC_SWITCH = '/xosapi/v1/fabric/switches'
SWITCH_PORT = '/xosapi/v1/fabric/switchports'
PORT_INTERFACE = '/xosapi/v1/fabric/portinterfaces'
OSS_SERVICE = '/xosapi/v1/hippie-oss/hippieossservices'
OSS_SERVICEINSTANCE = '/xosapi/v1/hippie-oss/hippieossserviceinstances'
OSS_VOLT = '/xosapi/v1/core/servicedependencys'
BNG_MAP = '/xosapi/v1/fabric-crossconnect/bngportmappings'
ATT_SERVICE = '/xosapi/v1/att-workflow-driver/attworkflowdriverservices'
ATT_WHITELIST = '/xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries'
