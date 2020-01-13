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

from utils.readProperties import readProperties


class restApi(object):
    """
    Functions for testing CORD API with POST, GET, PUT, DELETE method
    """

    def __init__(self, propertyFile="RestApiProperties.py"):
        self.rp = readProperties(
            os.path.abspath(os.path.join(
                os.path.dirname(__file__),
                "../Properties/",
                propertyFile,
            ))
        )
        self.controllerIP = self.getValueFromProperties("SERVER_IP")
        self.controllerPort = self.getValueFromProperties("SERVER_PORT")
        self.user = self.getValueFromProperties("XOS_USER")
        self.password = self.getValueFromProperties("XOS_PASSWD")
        self.jsonHeader = {"Content-Type": "application/json"}

    def getValueFromProperties(self, key):
        """
        Get and return values from properties file
        """
        try:
            rawValue = self.rp.getValueProperties(key)
            value = rawValue.replace("'", "")
        except BaseException:
            value = None

        # Allow override from environment
        if key in os.environ:
            value = os.environ[key]

        return value

    def getURL(self, key):
        """
        Get REST API suffix from key and return the full URL
        """
        urlSuffix = self.getValueFromProperties(key)
        url = "http://" + self.controllerIP + ":" + self.controllerPort + urlSuffix
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
            url, data=data, headers=self.jsonHeader, auth=(self.user, self.password)
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
            url, data=data, headers=self.jsonHeader, auth=(self.user, self.password)
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
        resp = requests.get(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiChameleonGet(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("get url...", url)
        resp = requests.get(url, auth=(self.user, self.password))
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
            url, data=data, headers=self.jsonHeader, auth=(self.user, self.password)
        )
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiChameleonPut(self, key, jsonData, urlSuffix=""):
        print("urlSuffix....", type(urlSuffix))
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("url", url)
        data = json.dumps(jsonData)
        resp = requests.put(
            url, data=data, headers=self.jsonHeader, auth=(self.user, self.password)
        )
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + str(urlSuffix)
        print("url", url)
        resp = requests.delete(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.no_content)
        return passed

    def ApiChameleonDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print("url", url)
        resp = requests.delete(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(
            resp, requests.codes.ok
        )
        return passed
