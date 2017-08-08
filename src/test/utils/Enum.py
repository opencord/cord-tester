
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


# 
# Copyright 2016-present Ciena Corporation
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
#
#!python
import copy
import pprint
pf = pprint.pformat

class EnumException(Exception):
    pass
class Enumeration(object):
    def __init__(self, name, enumList, valuesAreUnique=False, startValue=0):
        self.__doc__ = name
        self.uniqueVals = valuesAreUnique
        self.lookup = {}
        self.reverseLookup = {}

        self._addEnums(enumList, startValue)

    def _addEnums(self, enumList, startValue):
        i = startValue
        for x in enumList:
            if type(x) is tuple:
                try:
                    x, i = x
                except ValueError:
                    raise EnumException, "tuple doesn't have 2 items: %r" % (x,)
            if type(x) is not str:
                raise EnumException, "enum name is not a string: %r" % (x,)
            if x in self.lookup:
                raise EnumException, "enum name is not unique: %r" % (x,)
            if self.uniqueVals and i in self.reverseLookup:
                raise EnumException, "enum value %r not unique for %r" % (i, x)
            self.lookup[x] = i
            self.reverseLookup[i] = x

            if type(i) is int:
                i = i + 1

        values = self.lookup.values()
        self.first_int  = min(values)
        self.last_int   = max(values)
        self.first_name = self.reverseLookup[self.first_int]
        self.last_name  = self.reverseLookup[self.last_int]

    def __str__(self):
        return pf(self.lookup)

    def __repr__(self):
        return pf(self.lookup)

    def __eq__(self, other):
        return isinstance(other, Enumeration) and self.__doc__ == other.self.__doc__ and 0 == cmp(self.lookup, other.lookup)

    def extend(self, enumList):
        '''
        Extend an existing enumeration with additional values.
        '''
        startValue = self.last_int + 1
        self._addEnums(enumList, startValue)

    def __getattr__(self, attr):
        try: return self.lookup[attr]
        except KeyError: raise AttributeError, attr

    def whatis(self,value):
        return self.reverseLookup[value]

    def toInt(self, strval):
        return self.lookup.get(strval)

    def toStr(self,value):
        return self.reverseLookup.get(value,"Value undefined: %s" % str(value))

    def range(self):
        keys = copy.copy(self.reverseLookup.keys())
        keys.sort()
        return keys

    def valid(self, value):
        return value in self.reverseLookup.keys()

    def invalid(self, value):
        return value not in self.reverseLookup.keys()

    def vrange(self):
        ''' returns an iterator of the enumeration values '''
        return copy.copy(self.lookup.keys())

    def first_asInt(self):
        return self.first_int

    def last_asInt(self):
        return self.last_int

    def first_asName(self):
        return self.first_name

    def last_asName(self):
        return self.last_name

if __name__ == '__main__':
    #lets test things

    testEnum0 = Enumeration("EnumName0",
        ("Value0","Value1","Value2","Value3","Value4","Value5","Value6"))

    print testEnum0.Value6

    if testEnum0.__getattr__("Value6") == testEnum0.Value6:
        print "Looks good"

    # This is a bad case, we inserted a non-string value which should case
    # an exception.
#    testEnum1 = Enumeration("EnumName1",
#        ("Value0","Value1","Value2",1,"Value3","Value4","Value5","Value6"))

