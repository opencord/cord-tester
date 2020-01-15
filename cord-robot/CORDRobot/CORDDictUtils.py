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

import json
import uuid
import random
import yaml
import glob
import string


class CORDDictUtils(object):
    @staticmethod
    def listToDict(alist, intListIndex):
        dictInfo = alist[int(intListIndex)]
        return dictInfo

    @staticmethod
    def jsonToList(strFile, strListName):
        data = json.loads(open(strFile).read())
        # print "data...",data
        dataList = data[strListName]
        return dataList

    def readFile(self, path, single=True):
        dataDict = {}
        for fileName in glob.glob(path):
            print("Reading ", fileName)
            data = open(fileName).read()
            dataDict[fileName] = data
            if bool(single):
                return data
        if not dataDict:
            print("Failed to find the file!")
            return None
        return dataDict

    def readFiles(self, path):
        return self.readFile(path, single=False)

    """
    @method compare_dict
    @Description: validates if contents of dict1 exists in dict2
    @params: dict1 = input_data entered through api
             dict2 = retrieved data from GET method
    returns True if contents of dict1 exists in dict2
    """

    def compare_dict(self, dict1, dict2):
        print("input data", dict1)
        print("get data", dict2)
        if dict1 is None or dict2 is None:
            return False
        if not isinstance(dict1, dict) or not isinstance(dict2, dict):
            return False
        if dict1 == {}:
            return True
        return self.compare_dict_recursive(dict1, dict2)

    """
    @method compare_dict_recursive
    @Description: recursive function to validate if dict1 is a subset of dict2
    returns True if contents of dict1 exists in dict2
    """

    def compare_dict_recursive(self, dict1, dict2):
        for key1, value1 in dict1.items():
            if key1 not in dict2.keys():
                print("Missing key", key1, "in dict2")
                return False
            value2 = dict2[key1]
            if isinstance(value1, dict) and isinstance(value2, dict):
                if not self.compare_dict_recursive(value1, value2):
                    return False
            else:
                if value2 != value1:
                    print("Values of key", key1, "in two dicts are not equal")
                    return False
        return True

    """
    @method compare_list_of_dicts
    @Description: validates if contents of dicts in list1 exists in dicts of list2
    returns True if for each dict in list1, there's a dict in list2 that contains its content
    """

    def compare_list_of_dicts(self, list1, list2):
        for dict1 in list1:
            if dict1 == {}:
                continue
            key = dict1.keys()[0]
            value = dict1[key]
            dict2 = self.getDictFromListOfDict(list2, key, value)
            if dict2 == {}:
                print(
                    "Comparison failed: no dictionaries found in list2 with key",
                    key,
                    "and value",
                    value,
                )
                return False
            if not self.compare_dict(dict1, dict2):
                print(
                    "Comparison failed: dictionary",
                    dict1,
                    "is not a subset of dictionary",
                    dict2,
                )
                return False
        return True

    """
    @method search_dictionary
    @Description: Searches for a key in the provided nested dictionary
    @params: input_dict = dictionary to be searched
             search_key = name of the key to be searched for
    returns two values: search_key value and status of the search.
             True if found (False when not found)

    """

    def search_dictionary(self, input_dict, search_key):
        input_keys = input_dict.keys()
        key_value = ""
        found = False
        for key in input_keys:
            if key == search_key:
                key_value = input_dict[key]
                found = True
                break
            elif isinstance(input_dict[key], dict):
                key_value, found = self.search_dictionary(
                    input_dict[key], search_key)
                if found:
                    break
            elif isinstance(input_dict[key], list):
                if not input_dict[key]:
                    found = False
                    break
                for item in input_dict[key]:
                    if isinstance(item, dict):
                        key_value, found = self.search_dictionary(
                            item, search_key)
                        if found:
                            break
        return key_value, found

    """
    @method getDictFromListOfDict
        return key_value,found
    @Description: Searches for the dictionary in the provided list of dictionaries
                  that matches the value of the key provided
    @params : List of dictionaries(getResponse Data from the URL),
             SearchKey - Key that needs to be searched for (ex: account_num)
             searchKeyValue - Value of the searchKey (ex: 21)
    @Returns: Dictionary returned when match found for searchKey with the corresponding
             searchKeyValue provided
    """

    def getDictFromListOfDict(self, getJsonDataList,
                              searchKey, searchKeyValue):
        return_dict = {}
        result = ""
        for data in getJsonDataList:
            print("data", data)
            return_dict = {}
            found = False
            input_keys = data.keys()
            for key in input_keys:
                if key == searchKey and str(data[key]) == str(searchKeyValue):
                    found = True
                    return_dict = data
                    print("return_dict", return_dict)
                    break
                elif isinstance(data[key], dict):
                    result, found = self.search_dictionary(
                        data[key], searchKey)
                    if found and str(result) == str(searchKeyValue):
                        return_dict = data
                        break
                elif isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, dict):
                            result, found = self.search_dictionary(
                                data[key], searchKey)
                            if found and str(
                                    result) == str(searchKeyValue):
                                return_dict = data
                                break
            if return_dict:
                break
        return return_dict

    """
    @method getFieldValueFromDict
    @params : search_dict - Dictionary to be searched
             field - Key to be searched for (ex: account_num)
    @Returns: Returns the value of the Key that was provided
    """

    def getFieldValueFromDict(self, search_dict, field):
        results = ""
        found = False
        input_keys = search_dict.keys()
        for key in input_keys:
            print("key...", key)
            if key == field:
                results = search_dict[key]
                if not results:
                    found = True
                    break
            elif isinstance(search_dict[key], dict):
                results, found = self.search_dictionary(
                    search_dict[key], field)
                if found:
                    break
            elif isinstance(search_dict[key], list):
                if not search_dict[key]:
                    found = False
                    continue
                for item in search_dict[key]:
                    if isinstance(item, dict):
                        results, found = self.search_dictionary(item, field)
                        if found:
                            break
            if results:
                break

        return results

    def setFieldValueInDict(self, input_dict, field, field_value):
        input_dict[field] = field_value
        return input_dict

    """
    @method getAllFieldValues
    @params : getJsonDataDictList - List of dictionaries to be searched
             fieldName - Key to be searched for (ex: instance_id)
    @Returns: Returns the unique value of the Key that was provided
    """

    def getAllFieldValues(self, getJsonDataDictList, fieldName):
        value_list = []
        # uniqValue = ""  - this is unused, commented out
        uniq_list = []
        for data in getJsonDataDictList:
            fieldValue = ""
            fieldValue = self.getFieldValueFromDict(data, fieldName)
            value_list.append(fieldValue)
        uniq_list = sorted(set(value_list))
        if len(uniq_list) == 1:
            pass  # see above, unused?
            # uniqValue = uniq_list[0]
        else:
            print("list of values found for ", fieldName, ";", uniq_list)
        return fieldValue

    def generate_uuid(self):
        return uuid.uuid4()

    def generate_random_number_from_blacklist(
        self, blacklist, min=100, max=500, typeTag=False
    ):
        num = None
        while num in blacklist or num is None:
            num = random.randrange(int(min), int(max))
        if typeTag:
            return num
        else:
            return str(num)

    def get_dynamic_resources(self, inputfile, resource):
        resourceNames = []
        names = {}
        dnames = []
        with open(inputfile, "r") as f:
            contents = yaml.load(f)
        resources = contents[resource]
        for i in resources:
            resourceNames.append(i["name"])
        for i in resourceNames:
            names["name"] = i
            dnames.append(names.copy())
        return dnames

    def generate_random_value(
            self, value, max_length=10, min_int=1, max_int=10000):
        if value == "string":
            return "".join(
                random.choice(string.ascii_lowercase + string.digits)
                for _ in range(max_length)
            )
        if value == "bool":
            return random.choice([True, False])
        if value == "int32" or value == "uint32":
            return random.randint(min_int, max_int)
        if value == "float":
            return random.uniform(1, 10)
        if value == "role":
            return "admin"
        if value == "direction":
            return random.choice(["in", "out"])
        if value == "flavor":
            return random.choice(["m1.large", "m1.medium", "m1.small"])
        if value == "vlan_tag":
            return random.choice(["555", "1-4096", "ANY"])
        if value == "ip_address":
            return ".".join(str(random.randint(0, 255)) for _ in range(4))
        else:
            return None

    def generate_random_slice_name(self):
        random_name = "".join(
            random.choice(
                string.ascii_lowercase +
                string.digits) for _ in range(10))
        return "testloginbase" + random_name
