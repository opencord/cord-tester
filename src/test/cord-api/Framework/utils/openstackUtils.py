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