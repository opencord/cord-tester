#!/usr/bin/env python
import requests, json, sys, time
sys.path.append('utils')
from readProperties import readProperties

class RestApi(object):
    '''
    Functions for testing CORD API with POST, GET, PUT, DELETE method
    '''
    def __init__(self):
        self.rp = readProperties("../Properties/RestApiProperties.py")
        self.controllerIP = self.getValueFromProperties("SERVER_IP")
        self.controllerPort = self.getValueFromProperties("SERVER_PORT")
        self.user = self.getValueFromProperties("USER")
        self.password = self.getValueFromProperties("PASSWD")
        self.jsonHeader = {'Content-Type': 'application/json'}

    def getValueFromProperties(self, key):
        '''
        Get and return values from properties file
        '''
        rawValue = self.rp.getValueProperties(key)
        value = rawValue.replace("'","")
        return value

    def getURL(self, key):
        '''
        Get REST API suffix from key and return the full URL
        '''
        urlSuffix =  self.getValueFromProperties(key)
        url = "http://" + self.controllerIP + ":" + self.controllerPort + urlSuffix
        return url

    def checkResult(self, resp, expectedStatus):
        '''
        Check if the status code in resp equals to the expected number.
        Return True or False based on the check result.
        '''
        if resp.status_code == expectedStatus:
            print "Test passed: " + str(resp.status_code) + ": " + resp.text
            return True
        else:
            print "Test failed: " + str(resp.status_code) + ": " + resp.text
            return False

    def getSubscriberIdFromAccountNum(self, jsonDataList, accountNum):
        '''
        Search in each json data in the given list to find and return the
        subscriber id that corresponds to the given account number.
        '''
        # Here we assume subscriber id starts from 1
        subscriberId = 0
        try:
            for jsonData in jsonDataList:
                if jsonData["identity"]["account_num"] == str(accountNum):
                    subscriberId = jsonData["id"]
                    break
            return subscriberId
        except KeyError:
            print "Something wrong with the json data provided: ", jsonData
            return -1

    def ApiPost(self, key, jsonData):
        url = self.getURL(key)
        data = json.dumps(jsonData)
        resp = requests.post(url, data=data, headers=self.jsonHeader, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.created)
        return passed

    def ApiGet(self, key, urlSuffix=""):
        url = self.getURL(key) + urlSuffix
        resp = requests.get(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiPut(self, key, jsonData, urlSuffix=""):
        url = self.getURL(key) + urlSuffix
        data = json.dumps(jsonData)
        resp = requests.put(url, data=data, headers=self.jsonHeader, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + urlSuffix
        resp = requests.delete(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.no_content)
        return passed

if __name__ == '__main__':
    test = RestApi()
    key = "TENANT_SUBSCRIBER"
    account_num = 5
    result = test.ApiPost(key, {"identity":{"account_num":str(account_num)}})
    time.sleep(5)
    result = test.ApiGet(key)
    subId = test.getSubscriberIdFromAccountNum(result, account_num)
    urlSuffix = str(subId) + "/"
    time.sleep(5)
    result = test.ApiPut(key, {"identity":{"name":"My House 2"}}, urlSuffix)
    time.sleep(5)
    result = test.ApiDelete(key, urlSuffix)
