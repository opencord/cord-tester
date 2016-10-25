import pexpect,os
import time
import json
import collections
import sys
import robot
import os.path
from os.path import expanduser

class utils(object):

    @staticmethod
    def listToDict(alist, intListIndex):
        dictInfo = alist[int(intListIndex)]
        return dictInfo

    @staticmethod
    def jsonToList(strFile, strListName):
        data = json.loads(open(strFile).read())
        #print "data...",data
        dataList = data[strListName]
        return dataList

    '''
    @method compare_dict
    @Description: validates if contents of dict1 exists in dict2
    @params: dict1 = input_data entered through api
             dict2 = retrieved data from GET method
    returns True if contents of dict1 exists in dict2
    '''

    @staticmethod
    def compare_dict(dict1, dict2):
        print "input_data", dict1
        print "get data", dict2
        if dict1 == None or dict2 == None:
           return False

        if type(dict1) is not dict or type(dict2) is not dict:
           return False

        for key1,value1 in dict1.items():
            try:
                if key1 in dict2:
                   for key2, value2 in value1.items():
                       if value2 != dict2[key1][key2]:
                          return False
            except:
	        print "Additional items"
        return True

#Test
#test = utils()
#data=test.jsonToList("Subscribers.json","SubscriberInfo")
#print  test.jsonToList("Subscribers.json","SubscriberInfo")
#print "index 1...",test.listToDict(data,1)

