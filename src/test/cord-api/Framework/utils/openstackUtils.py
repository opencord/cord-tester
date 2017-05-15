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

'''
get_neutron_lists("""
    +--------------------------------------+------------------------+----------------------------------------------------+
    | id                                   | name                   | subnets                                            |
    +--------------------------------------+------------------------+----------------------------------------------------+
    | 23af870c-f52d-4237-bfc9-6f5c435a3e2b | public                 | 828566dc-e639-487a-90b8-55a281399230 10.6.1.192/26 |
    | 57b9c85e-1717-400a-a917-f1b92a028c33 | test-network           | 44e231c7-4f45-4286-b9c7-89eaa92529a5 2.2.2.0/24    |
    | c439e0ee-8035-43db-9346-4a099e44e12a | exampleservice_network | 9af47c90-de4a-457f-b5ce-a15d7034e003 10.0.4.0/24   |
    | ee4d176e-68af-49e8-91e2-977eece99d76 | mysite_vsg-access      | 180b5311-e207-449f-b1a3-5feefc60971b 10.0.2.0/24   |
    | eee4e9ae-abc5-4704-aaaa-bf0788bcd088 | management             | c74ec67c-8083-43f0-8477-99c4a6e937ba 172.27.0.0/24 |
    +--------------------------------------+------------------------+----------------------------------------------------+ """)
'''
print get_nova_lists("""
    +--------------------------------------+-------------------------+--------+------------+-------------+---------------------------------------------------------------------------+
    | ID                                   | Name                    | Status | Task State | Power State | Networks                                                                  |
    +--------------------------------------+-------------------------+--------+------------+-------------+---------------------------------------------------------------------------+
    | a7c71d76-dc6c-400a-9e1b-f884431a3214 | mysite_exampleservice-2 | ACTIVE | -          | Running     | exampleservice_network=10.0.4.2; management=172.27.0.3; public=10.6.1.194 |
    | e4f6bdec-f06c-4e88-bd98-764f391f0df3 | mysite_test-1-3         | ACTIVE | -          | Running     | management=172.27.0.4; test-network=2.2.2.2                               |
    | f24312b4-e8cd-4a57-bf72-65e84ab6653d | mysite_vsg-1            | ACTIVE | -          | Running     | management=172.27.0.2; mysite_vsg-access=10.0.2.2                         |
    | 0649305a-0938-496e-86af-51a48d1b6007 | mysite_vsg-4            | ACTIVE | -          | Running     | management=172.27.0.5; mysite_vsg-access=10.0.2.3                         |
    | d6dc15bd-3815-416a-9e64-2e8496251fce | mysite_vsg-5            | ACTIVE | -          | Running     | management=172.27.0.6; mysite_vsg-access=10.0.2.4                         |
    +--------------------------------------+-------------------------+--------+------------+-------------+---------------------------------------------------------------------------+ """
                     )