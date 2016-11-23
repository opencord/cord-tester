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

    '''
    @method search_dictionary
    @Description: Searches for a key in the provided nested dictionary
    @params: input_dict = dictionary to be searched
             search_key = name of the key to be searched for
    returns two values: search_key value and status of the search.
             True if found (False when not found)

    '''
    def search_dictionary(self,input_dict, search_key):
        input_keys = input_dict.keys()
        key_value = ''
        found = False
        for key in input_keys:
            if key == search_key:
               key_value = input_dict[key]
               found = True
               break
            elif type(input_dict[key]) == dict:
                 key_value, found = self.search_dictionary(input_dict[key],search_key)
                 if found == True:
                    break
            elif type(input_dict[key]) == list:
                 if not input_dict[key]:
                    found = False
                    break
                 for item in input_dict[key]:
                     if isinstance(item, dict):
                        key_value, found = self.search_dictionary(item, search_key)
                        if found == True:
                           break
        return key_value,found
    '''
    @method getDictFromListOfDict
        return key_value,found
    @Description: Searches for the dictionary in the provided list of dictionaries
                  that matches the value of the key provided
    @params : List of dictionaries(getResponse Data from the URL),
             SearchKey - Key that needs to be searched for (ex: account_num)
             searchKeyValue - Value of the searchKey (ex: 21)
    @Returns: Dictionary returned when match found for searchKey with the corresponding
             searchKeyValue provided
    '''

    def getDictFromListOfDict(self, getJsonDataList, searchKey, searchKeyValue):
        return_dict = {}
        result = ''
        for data in getJsonDataList:
            return_dict = {}
            found = False
            input_keys = data.keys()
            for key in input_keys:
                if key == searchKey and str(data[key]) == str(searchKeyValue):
                   found = True
                   return_dict = data
                   break
                elif type(data[key]) == dict:
                     result, found = self.search_dictionary(data[key],searchKey)
                     if found == True and str(result) == str(searchKeyValue):
                        return_dict = data
                        break
                elif type(data[key]) == list:
                     for item in data[key]:
                         if isinstance(item, dict):
                            result, found = self.search_dictionary(data[key], searchKey)
                            if found == True and str(result) == str(searchKeyValue):
                               return_dict = data
                               break
            if return_dict:
               break
        return return_dict


    '''
    @method getFieldValueFromDict
    @params : search_dict - Dictionary to be searched
             field - Key to be searched for (ex: account_num)
    @Returns: Returns the value of the Key that was provided
    '''
    def getFieldValueFromDict(self,search_dict, field):
        print "search_dict", search_dict, "field...", field
        results = ''
        found = False
        input_keys = search_dict.keys()
        for key in input_keys:
            print "key...", key
            if key == field:
               print "entered if..."
               results = search_dict[key]
               print "results...", results
               if not results:
                  found = True
                  break
            elif type(search_dict[key]) == dict:
                 results, found = self.search_dictionary(search_dict[key],field)
                 if found == True:
                    break
            elif type(search_dict[key]) == list:
                 if not search_dict[key]:
                    found = False
                    break
                 for item in search_dict[key]:
                     if isinstance(item, dict):
                        results, found = self.search_dictionary(item, field)
                        if found == True:
                           break
            if results:
               break

        return results

    def setFieldValueInDict(self,input_dict,field,field_value):
        input_dict[field]=field_value
        return input_dict

'''
#Test
dict_list = {
 "humanReadableName": "cordSubscriber-17",
        "id": 17,
        "features": {
            "uplink_speed": 1000000000,
            "downlink_speed": 1000000000,
            "status": "enabled"
        },
        "identity": {
            "account_num": "20",
            "name": "My House"
        },
        "related": {}
    }
input_dict = {
 "s_tag" : "111",
 "c_tag" : "222",
 "subscriber" : ""
 }
new_value = 3
test = utils()
#data=test.jsonToList("Subscribers.json","SubscriberInfo")
#print  test.jsonToList("Subscribers.json","SubscriberInfo")
#print "index 1...",test.listToDict(data,1)
#result = test.getDictFromListOfDict(dict_list,"email",21)
#result = test.getFieldValueFromDict(dict_list,"id")
#result = test.getDictFromListOfDict(dict_list,"account_num",21)
result = test.setFieldValueInDict(input_dict,"subscriber",new_value)
print "finalllllll result....", result
'''
