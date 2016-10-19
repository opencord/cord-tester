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

#Test
#test = utils()
#data=test.jsonToList("Subscribers.json","SubscriberInfo")
#print  test.jsonToList("Subscribers.json","SubscriberInfo")
#print "index 1...",test.listToDict(data,1)

