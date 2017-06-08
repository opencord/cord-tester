import pexpect,os
import time
import json
import collections
import sys
import robot
import os.path
from os.path import expanduser
import uuid

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
    def compare_dict(self, dict1, dict2):
        print "input data", dict1
        print "get data", dict2
        if dict1 == None or dict2 == None:
           return False
        if type(dict1) is not dict or type(dict2) is not dict:
           return False
        if dict1 == {}:
            return True
        return self.compare_dict_recursive(dict1, dict2)

    '''
    @method compare_dict_recursive
    @Description: recursive function to validate if dict1 is a subset of dict2
    returns True if contents of dict1 exists in dict2
    '''
    def compare_dict_recursive(self, dict1, dict2):
        for key1,value1 in dict1.items():
            if key1 not in dict2.keys():
                print "Missing key", key1, "in dict2"
                return False
            value2 = dict2[key1]
            if type(value1) is dict and type(value2) is dict:
                if not self.compare_dict_recursive(value1, value2):
                    return False
            else:
                if value2 != value1:
                    print "Values of key", key1, "in two dicts are not equal"
                    return False
        return True

    '''
    @method compare_list_of_dicts
    @Description: validates if contents of dicts in list1 exists in dicts of list2
    returns True if for each dict in list1, there's a dict in list2 that contains its content
    '''
    def compare_list_of_dicts(self, list1, list2):
        for dict1 in list1:
            if dict1 == {}:
                continue
            key = dict1.keys()[0]
            value = dict1[key]
            dict2 = self.getDictFromListOfDict(list2, key, value)
            if dict2 == {}:
                print "Comparison failed: no dictionaries found in list2 with key", key, "and value", value
                return False
            if self.compare_dict(dict1, dict2) == False:
                print "Comparison failed: dictionary", dict1, "is not a subset of dictionary", dict2
                return False
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
            print "data..",data
            return_dict = {}
            found = False
            input_keys = data.keys()
            for key in input_keys:
                print "key in input_keys...",key
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
        results = ''
        found = False
        input_keys = search_dict.keys()
        for key in input_keys:
            print "key...", key
            if key == field:
               results = search_dict[key]
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
                    continue
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
    @method getAllFieldValues
    @params : getJsonDataDictList - List of dictionaries to be searched
             fieldName - Key to be searched for (ex: instance_id)
    @Returns: Returns the unique value of the Key that was provided
    '''

    def getAllFieldValues(self, getJsonDataDictList, fieldName):
        value_list = []
        uniqValue = ''
        uniq_list = []
        for data in getJsonDataDictList:
            fieldValue = ''
            fieldValue = self.getFieldValueFromDict(data, fieldName)
            value_list.append(fieldValue)
        uniq_list = sorted(set(value_list))
        if len(uniq_list) == 1:
           uniqValue = uniq_list[0]
        else:
           print "list of values found for ", fieldName, ";", uniq_list
        return fieldValue

    def generate_uuid(self):
        return uuid.uuid4()

'''
#Test
dict_list = {
[
    {
        "humanReadableName": "mysite_vsg-1",
        "validators": {
            "policed": [],
            "creator": [],
            "ip": [],
            "image": [
                "notBlank"
            ],
            "backend_register": [
                "notBlank"
            ],
            "flavor": [
                "notBlank"
            ],
            "backend_status": [
                "notBlank"
            ],
            "id": [],
            "instance_name": [],
            "slice": [
                "notBlank"
            ],
            "backend_need_delete": [],
            "enacted": [],
            "no_sync": [],
            "node": [
                "notBlank"
            ],
            "userData": [],
            "updated": [
                "notBlank"
            ],
            "parent": [],
            "deleted": [],
            "lazy_blocked": [],
            "deployment": [
                "notBlank"
            ],
            "backend_need_reap": [],
            "instance_uuid": [],
            "numberCores": [
                "notBlank"
            ],
            "name": [
                "notBlank"
            ],
            "created": [],
            "write_protect": [],
            "isolation": [
                "notBlank"
            ],
            "no_policy": [],
            "instance_id": [],
            "volumes": []
        },
        "id": 1,
        "created": "2017-03-13T22:23:48.805109Z",
        "updated": "2017-03-13T22:38:06.084074Z",
        "enacted": "2017-03-13T22:38:43.894253Z",
        "policed": "2017-03-13T22:38:08.086489Z",
        "backend_register": "{\"next_run\": 0, \"last_success\": 1489444729.019414, \"exponent\": 0}",
        "backend_status": "1 - OK",
        "instance_id": "instance-00000001",
        "instance_uuid": "a46d716f-e82c-4088-a042-72c3a97ed3ff",
        "name": "mysite_vsg",
        "instance_name": "mysite_vsg-1",
        "ip": "10.1.0.17",
        "image": "http://ms1333.utah.cloudlab.us:8080/api/core/images/1/",
        "creator": "http://ms1333.utah.cloudlab.us:8080/api/core/users/1/",
        "slice": "http://ms1333.utah.cloudlab.us:8080/api/core/slices/2/",
        "deployment": "http://ms1333.utah.cloudlab.us:8080/api/core/deployments/1/",
        "node": "http://ms1333.utah.cloudlab.us:8080/api/core/nodes/1/",
        "numberCores": 0,
        "flavor": "http://ms1333.utah.cloudlab.us:8080/api/core/flavors/1/",
        "isolation": "vm",
        "volumes": "/etc/dnsmasq.d,/etc/ufw",
        "networks": [
            "http://ms1333.utah.cloudlab.us:8080/api/core/networks/1/",
            "http://ms1333.utah.cloudlab.us:8080/api/core/networks/2/"
        ]
    },
    {
        "humanReadableName": "mysite_exampleservice-2",
        "validators": {
            "policed": [],
            "creator": [],
            "ip": [],
            "image": [
                "notBlank"
            ],
            "backend_register": [
                "notBlank"
            ],
            "flavor": [
                "notBlank"
            ],
            "backend_status": [
                "notBlank"
            ],
            "id": [],
            "instance_name": [],
            "slice": [
                "notBlank"
            ],
            "backend_need_delete": [],
            "enacted": [],
            "no_sync": [],
            "node": [
                "notBlank"
            ],
            "userData": [],
            "updated": [
                "notBlank"
            ],
            "parent": [],
            "deleted": [],
            "lazy_blocked": [],
            "deployment": [
                "notBlank"
            ],
            "backend_need_reap": [],
            "instance_uuid": [],
            "numberCores": [
                "notBlank"
            ],
            "name": [
                "notBlank"
            ],
            "created": [],
            "write_protect": [],
            "isolation": [
                "notBlank"
            ],
            "no_policy": [],
            "instance_id": [],
            "volumes": []
        },
        "id": 2,
        "created": "2017-03-13T22:38:03.872267Z",
        "updated": "2017-03-13T22:38:06.047153Z",
        "enacted": "2017-03-13T22:39:07.002800Z",
        "policed": "2017-03-13T22:38:07.895147Z",
        "backend_register": "{\"next_run\": 0, \"last_success\": 1489444774.726988, \"exponent\": 0}",
        "backend_status": "1 - OK",
        "instance_id": "instance-00000002",
        "instance_uuid": "cb219739-0d11-48a2-9f19-1e2aba1f004e",
        "name": "mysite_exampleservice",
        "instance_name": "mysite_exampleservice-2",
        "ip": "10.1.0.17",
        "image": "http://ms1333.utah.cloudlab.us:8080/api/core/images/3/",
        "creator": "http://ms1333.utah.cloudlab.us:8080/api/core/users/1/",
        "slice": "http://ms1333.utah.cloudlab.us:8080/api/core/slices/4/",
        "deployment": "http://ms1333.utah.cloudlab.us:8080/api/core/deployments/1/",
        "node": "http://ms1333.utah.cloudlab.us:8080/api/core/nodes/1/",
        "numberCores": 0,
        "flavor": "http://ms1333.utah.cloudlab.us:8080/api/core/flavors/1/",
        "isolation": "vm",
        "networks": [
            "http://ms1333.utah.cloudlab.us:8080/api/core/networks/3/",
            "http://ms1333.utah.cloudlab.us:8080/api/core/networks/1/",
            "http://ms1333.utah.cloudlab.us:8080/api/core/networks/4/"
        ]
    },
    {
        "humanReadableName": "mysite_vsg-3",
        "validators": {
            "policed": [],
            "creator": [],
            "ip": [],
            "image": [
                "notBlank"
            ],
            "backend_register": [
                "notBlank"
            ],
            "flavor": [
                "notBlank"
            ],
            "backend_status": [
                "notBlank"
            ],
            "id": [],
            "instance_name": [],
            "slice": [
                "notBlank"
            ],
            "backend_need_delete": [],
            "enacted": [],
            "no_sync": [],
            "node": [
                "notBlank"
            ],
            "userData": [],
            "updated": [
                "notBlank"
            ],
            "parent": [],
            "deleted": [],
            "lazy_blocked": [],
            "deployment": [
                "notBlank"
            ],
            "backend_need_reap": [],
            "instance_uuid": [],
            "numberCores": [
                "notBlank"
            ],
            "name": [
                "notBlank"
            ],
            "created": [],
            "write_protect": [],
            "isolation": [
                "notBlank"
            ],
            "no_policy": [],
            "instance_id": [],
            "volumes": []
        },
        "id": 3,
        "created": "2017-03-17T23:15:13.556863Z",
        "updated": "2017-03-17T23:15:13.555271Z",
        "enacted": "2017-03-17T23:15:24.376854Z",
        "policed": "2017-03-17T23:15:14.991037Z",
        "backend_register": "{\"next_run\": 0, \"last_success\": 1489792538.996003, \"exponent\": 0}",
        "backend_status": "1 - OK",
        "instance_id": "instance-00000003",
        "instance_uuid": "ec5ece6d-bebe-4165-98c5-3a026a41c63c",
        "name": "mysite_vsg",
        "instance_name": "mysite_vsg-3",
        "ip": "10.1.0.17",
        "image": "http://ms1333.utah.cloudlab.us:8080/api/core/images/1/",
        "creator": "http://ms1333.utah.cloudlab.us:8080/api/core/users/1/",
        "slice": "http://ms1333.utah.cloudlab.us:8080/api/core/slices/2/",
        "deployment": "http://ms1333.utah.cloudlab.us:8080/api/core/deployments/1/",
        "node": "http://ms1333.utah.cloudlab.us:8080/api/core/nodes/1/",
        "numberCores": 0,
        "flavor": "http://ms1333.utah.cloudlab.us:8080/api/core/flavors/1/",
        "isolation": "vm",
        "volumes": "/etc/dnsmasq.d,/etc/ufw"
    }
   ]
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
result = test.getDictFromListOfDict(dict_list,"instance_name","mysite_vsg-3")
#result = test.getFieldValueFromDict(dict_list,"id")
#result = test.getDictFromListOfDict(dict_list,"account_num",21)
#result = test.setFieldValueInDict(input_dict,"subscriber",new_value)
#result = test.getAllFieldValues(list1,"instance_name")
print "finalllllll result....", result
'''
