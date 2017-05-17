#!/usr/bin/env python
import requests, json, os, sys, time
#sys.path.append('common-utils')
sys.path.append(os.path.join(sys.path[0],'utils'))
from readProperties import readProperties

class restApi(object):
    '''
    Functions for testing CORD API with POST, GET, PUT, DELETE method
    '''
    def __init__(self):
        self.rp = readProperties(os.path.abspath(os.path.dirname(__file__))+"/../Properties/RestApiProperties.py")
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
    '''
    @method getAccountNum
    @Returns AccountNumber for the subscriber
    @params: jsonData is Dictionary
    '''
    def getAccountNum(self, jsonData):
        print type(str(jsonData['identity']['account_num']))
        return jsonData['identity']['account_num']

    def getSubscriberId(self, jsonDataList, accountNum):
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
            return str(subscriberId)
        except KeyError:
            print "Something wrong with the json data provided: ", jsonData
            return -1
    '''
     Retrieve the correct jsonDict from the List of json objects returned
     from Get Reponse
     Account Number is the one used to post "Data"
    '''
    def getJsonDictOfAcctNum(self, getResponseList, AccountNum):
        getJsonDict = {}
        try:
            for data in getResponseList:
                if data['identity']['account_num'] == AccountNum:
                   getJsonDict = data
                   break
            return getJsonDict
        except KeyError:
            print "Could not find the related account number in Get Resonse Data"
            return -1

    def ApiPost(self, key, jsonData):
        url = self.getURL(key)
        data = json.dumps(jsonData)
        print "url, data..", url, data
        resp = requests.post(url, data=data, headers=self.jsonHeader, auth=(self.user, self.password))
        print "requests.codes.....",requests.codes.created
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiGet(self, key, urlSuffix=""):
        url = self.getURL(key) + str(urlSuffix)
        print "get url...",url
        resp = requests.get(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiChameleonGet(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print "get url...",url
        resp = requests.get(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        if not passed:
            return None
        else:
            return resp.json()

    def ApiPut(self, key, jsonData, urlSuffix=""):
        print "urlSuffix....",type(urlSuffix)
        url = self.getURL(key) + str(urlSuffix) + "/"
        data = json.dumps(jsonData)
        resp = requests.put(url, data=data, headers=self.jsonHeader, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiChameleonPut(self, key, jsonData, urlSuffix=""):
        print "urlSuffix....",type(urlSuffix)
        url = self.getURL(key) + "/" + str(urlSuffix)
        print "url", url
        data = json.dumps(jsonData)
        resp = requests.put(url, data=data, headers=self.jsonHeader, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.ok)
        return passed

    def ApiDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + str(urlSuffix)
        print "url",url
        resp = requests.delete(url, auth=(self.user, self.password))
        passed = self.checkResult(resp, requests.codes.no_content)
        return passed

    def ApiChameleonDelete(self, key, urlSuffix=""):
        url = self.getURL(key) + "/" + str(urlSuffix)
        print "url",url
        resp = requests.delete(url, auth=(self.user, self.password))
        #passed = self.checkResult(resp, requests.codes.no_content)
        passed = self.checkResult(resp, requests.codes.created) or self.checkResult(resp, requests.codes.ok)
        return passed

#test
'''
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
'''
'''
test = restApi()
#key = "UTILS_SYNCHRONIZER"
#key = "CORE_USERS"
#key2 = "UTILS_LOGIN"
#key = "TENANT_SUBSCRIBER"
#jsonGetData = test.ApiGet(key)
#jsonResponse = test.ApiPost(key,{"identity":{"name":"My House 22"}})
#jsonResponse = test.ApiPost(key,{"firstname":"Test002","lastname":"User002","email":"test002@onlab.us","password":"TestUser002","site": "http://localhost:8000/api/core/sites/1/"})
key = "VOLT_TENANT"
key = "VOLT_SUBSCRIBER"
#jsonResponse = test.ApiDelete(key,204)
#jsonResponse = test.ApiPut(key,{"firstname":"Test002","lastname":"User002","email":"test002update@onlab.us","password":"TestUser002","site": "http://localhost:8000/api/core/sites/1/"},14)
#jsonResponse = test.ApiPost(key2,{"username":"test002update@onlab.us","password":"TestUser002"})
#jsonResponse = test.ApiPost(key2,{"username":"padmin@vicci.org","password":"letmein"})
#jsonResponse = test.ApiPut(key,{"username":"testuser","password":"TestUser001"},"9")
#key = "CORE_INSTANCES"
#key1 = "CORE_SANITY_SLICES"
#key2 = "CORE_SLICES"
#input_dict = { "s_tag" : "111", "c_tag" : "222", "subscriber" : 23}
input_dict = {
         "s_tag" : 117,
         "c_tag" : 227
        }

#input_dict1 = { "name" : "mysite_Test1", "site" : 1 , "creator" : 1}
input_dict2 = {
 
            "cdn_enable": "true",
            "uplink_speed": 1000000000,
            "downlink_speed": 1000000000,
            "enable_uverse": "true",
            "status": "enabled",
            "service_specific_id": "100",
            "name": "My House"
    }
#jsonResponse = test.ApiPost(key,input_dict)
#jsonResponse = test.ApiChameleonPut(key,input_dict,12)
#jsonGetData = test.ApiGet(key,"/12")
#print "========="
#print jsonGetData
#jsonEdit = test.ApiPut(key,{"c_tag" : "666","s_tag" : "123"},"30")
jsonO = test.ApiDelete(key,"/7")
#jsonResponse = test.ApiPut(key,{"identity":{"name":"My House 22"}},"71")
#jsonResponse = test.ApiPost(key,{"name":"test-2"})
#jsonResponse = test.ApiPut(key,{"name":"test1-changed"},"9")
print "========="
'''
