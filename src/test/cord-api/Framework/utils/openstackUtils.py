
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


import time
import json
import collections
import sys
import os.path
import re

def get_neutron_lists(netlist):
    pairs = re.split("\+-*\+-*\+\n?",netlist)[2:-1]
    ids,names,subnets = [],[],[]
    for p in pairs:
      for l in p.split('\n'):
        pair = l.split('|')
        if len(pair) > 1:
          ids.append(pair[1].strip())
          names.append(pair[2].strip())
          subnets.append(pair[3].strip())
    nets = dict(zip(names,subnets))
    return nets

def get_nova_lists(novalist,nameWildCard=None):
    pairs = re.split("\+-*\+-*\+\n?",novalist)[2:-1]
    ids,names,status,taskState,powerState,networks = [],[],[],[],[],[]
    for p in pairs:
      for l in p.split('\n'):
        pair = l.split('|')
        if len(pair) > 1:
          ids.append(pair[1].strip())
          names.append(pair[2].strip())
          status.append(pair[3].strip())
          taskState.append(pair[4].strip())
          powerState.append(pair[5].strip())
          networks.append(pair[6].strip())
    instances = dict(zip(names,networks))
    if nameWildCard is not None:
        for key in instances.keys():
            if re.match(nameWildCard, key):
                return instances[key]
    else:
        return instances

def get_instance_status(novalist,nameWildCard=None):
    pairs = re.split("\+-*\+-*\+\n?",novalist)[2:-1]
    ids,names,status,taskState,powerState,networks = [],[],[],[],[],[]
    for p in pairs:
      for l in p.split('\n'):
        pair = l.split('|')
        if len(pair) > 1:
          ids.append(pair[1].strip())
          names.append(pair[2].strip())
          status.append(pair[3].strip())
          taskState.append(pair[4].strip())
          powerState.append(pair[5].strip())
          networks.append(pair[6].strip())
    instances = dict(zip(names,status))
    if nameWildCard is not None:
        for key in instances.keys():
            if re.match(nameWildCard, key):
                return instances[key]
    else:
        return instances