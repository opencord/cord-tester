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

from __future__ import absolute_import, print_function

import requests
import json
import os

# These are the default values used with XOS
restApiDefaults = {
    'ATT_SERVICE': '/xosapi/v1/att-workflow-driver/attworkflowdriverservices',
    'ATT_SERVICEINSTANCES': '/xosapi/v1/att-workflow-driver/attworkflowdriverserviceinstances',
    'ATT_WHITELIST': '/xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries',
    'BNG_MAP': '/xosapi/v1/fabric-crossconnect/bngportmappings',
    'CH_CORE_DEPLOYMENTS': '/xosapi/v1/core/deployments',
    'CH_CORE_FLAVORS': '/xosapi/v1/core/flavors',
    'CH_CORE_IMAGES': '/xosapi/v1/core/images',
    'CH_CORE_INSTANCES': '/xosapi/v1/core/instances',
    'CH_CORE_NETWORKS': '/xosapi/v1/core/networks',
    'CH_CORE_NETWORK_SLICES': '/xosapi/v1/core/networkslices',
    'CH_CORE_NETWORK_TEMPLATES': '/xosapi/v1/core/networktemplates',
    'CH_CORE_NODES': '/xosapi/v1/core/nodes',
    'CH_CORE_PORTS': '/xosapi/v1/core/ports',
    'CH_CORE_SERVICELINK': '/xosapi/v1/core/serviceinstancelinks',
    'CH_CORE_SERVICES': '/xosapi/v1/core/services',
    'CH_CORE_SERVICES': '/xosapi/v1/core/services',
    'CH_CORE_SITEDEPLOYMENTS': '/xosapi/v1/core/sitedeployments',
    'CH_CORE_SITES': '/xosapi/v1/core/sites',
    'CH_CORE_SLICES': '/xosapi/v1/core/slices',
    'CH_CORE_SLICES': '/xosapi/v1/core/slices',
    'CH_CORE_USERS': '/xosapi/v1/core/users',
    'CORE_DEPLOYMENTS': '/api/core/deployments/',
    'CORE_FLAVORS': '/api/core/flavors/',
    'CORE_IMAGES': '/api/core/images/',
    'CORE_INSTANCES': '/api/core/instances/',
    'CORE_NODES': '/api/core/nodes/',
    'CORE_SANITY_INSTANCES': '/api/core/instances/?no_hyperlinks=1',
    'CORE_SANITY_NODES': '/api/core/nodes/?no_hyperlinks=1',
    'CORE_SANITY_SLICES': '/api/core/slices/?no_hyperlinks=1',
    'CORE_SERVICES': '/api/core/services/',
    'CORE_SITEDEPLOYMENTS': '/api/core/sitedeployments',
    'CORE_SITES': '/api/core/sites/',
    'CORE_SLICES': '/api/core/slices/',
    'CORE_USERS': '/api/core/users/',
    'FABRIC_CROSSCONNECT_SERVICEINSTANCES': '/xosapi/v1/fabric-crossconnect/fabriccrossconnectserviceinstances',
    'FABRIC_SWITCH': '/xosapi/v1/fabric/switches',
    'HWVSG_TENANT': '/xosapi/v1/vsg-hw/vsghwserviceinstances',
    'ONU_DEVICE': '/xosapi/v1/volt/onudevices',
    'OSS_SERVICE': '/xosapi/v1/hippie-oss/hippieossservices',
    'OSS_SERVICEINSTANCE': '/xosapi/v1/hippie-oss/hippieossserviceinstances',
    'OSS_VOLT': '/xosapi/v1/core/servicedependencys',
    'PON_PORT': '/xosapi/v1/volt/ponports',
    'PORT_INTERFACE': '/xosapi/v1/fabric/portinterfaces',
    'SERVER_IP': '127.0.0.1',
    'SERVER_PORT': '30006',
    'SWITCH_PORT': '/xosapi/v1/fabric/switchports',
    'TENANT_SUBSCRIBER': '/api/tenant/cord/subscriber/',
    'TENANT_VOLT': '/api/tenant/cord/volt/',
    'UTILS_LOGIN': '/api/utility/login/',
    'UTILS_SYNCHRONIZER': '/api/utility/synchronizer/',
    'VOLT_DEVICE': '/xosapi/v1/volt/oltdevices',
    'VOLT_SERVICE': '/xosapi/v1/volt/voltservices',
    'VOLT_SUBSCRIBER': '/xosapi/v1/rcord/rcordsubscribers',
    'VOLT_TENANT': '/xosapi/v1/volt/voltserviceinstances',
    'VSG_TENANT': '/xosapi/v1/vsg/vsgserviceinstances',
    'XOS_PASSWD': 'letmein',
    'XOS_USER': 'admin@opencord.org',
}

jsonHeader = {"Content-Type": "application/json"}


class restApi():
    """
    Functions for testing CORD API with POST, GET, PUT, DELETE method
    """

    def getEnvOrDefault(self, key):
        """
        Find a variable in environment, or use Default value
        """
        if key in os.environ:
            value = os.environ[key]
        elif key in restApiDefaults:
            value = restApiDefaults[key]
        else:
            print("Unable to find '%s' in environment or defaults!" % key)
            value = None

        return value

    def getURL(self, key):
        """
        Get REST API suffix from key and return the full URL
        """
        urlSuffix = self.getEnvOrDefault(key)
        url = "http://" + self.getEnvOrDefault("SERVER_IP") + ":" + self.getEnvOrDefault("SERVER_PORT") + urlSuffix
        return url

    def checkResult(self, resp, expectedStatus):
        """
        Check if the status code in resp equals to the expected number.
        Return True or False based on the check result.
        """
        if resp.status_code == expectedStatus:
            print("Test passed: " + str(resp.status_code) + ": " + resp.text)
            return True
        else:
            print("Test failed: " + str(resp.status_code) + ": " + resp.text)
            return False

    def ApiPost(self, key, jsonData):
        url = self.getURL(key)
        data = json.dumps(jsonData)
        print("url, data..", url, data)
        resp = requests.post(
            url, data=data, headers=jsonHeader,
            auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD"))
        )
        print("requests.codes.....", requests.codes.created)
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(
            resp, requests.codes.ok
        )
        return passed

    def ApiPostReturnJson(self, key, jsonData):
        url = self.getURL(key)
        data = json.dumps(jsonData)
        print("url, data..", url, data)
        resp = requests.post(
            url, data=data, headers=jsonHeader,
            auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD"))
        )
        print("requests.codes.....", requests.codes.created)
        print("posted data...", resp.json())
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(
            resp, requests.codes.ok
        )
        return passed, resp.json()

    def ApiGet(self, key, urlSuffix=""):
        url = self.getURL(key) + str(urlSuffix)
        print("get url...", url)
        resp = requests.get(url, auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD")))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiChameleonGet(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("get url...", url)
        resp = requests.get(url, auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD")))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiPut(self, key, jsonData, urlSuffix=""):
        print("urlSuffix....", type(urlSuffix))
        url = self.getURL(key) + str(urlSuffix) + "/"
        data = json.dumps(jsonData)
        resp = requests.put(
            url, data=data, headers=jsonHeader,
            auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD"))
        )
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiChameleonPut(self, key, jsonData, urlSuffix=""):
        print("urlSuffix....", type(urlSuffix))
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("url", url)
        data = json.dumps(jsonData)
        resp = requests.put(
            url, data=data, headers=jsonHeader,
            auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD"))
        )
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + str(urlSuffix)
        print("url", url)
        resp = requests.delete(url, auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD")))
        passed = self.checkResult(resp, requests.codes.no_content)
        return passed

    def ApiChameleonDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("url", url)
        resp = requests.delete(url, auth=(self.getEnvOrDefault("XOS_USER"), self.getEnvOrDefault("XOS_PASSWD")))
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(
            resp, requests.codes.ok
        )
        return passed
