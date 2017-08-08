
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


#!/usr/bin/env python
#
# Definitions for RADIUS programs
#
# Copyright 2002 Miguel A.L. Paraz <mparaz@mparaz.com>
#
# This should only be used when testing modules.
# Inside freeradius, the 'radiusd' Python module is created by the C module
# and the definitions are automatically created.
#
# $Id: 02e9f237cc0df3d7be08413238e504b90bf59b1a $

# from modules.h

RLM_MODULE_REJECT = 0
RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_HANDLED = 3
RLM_MODULE_INVALID = 4
RLM_MODULE_USERLOCK = 5
RLM_MODULE_NOTFOUND = 6
RLM_MODULE_NOOP = 7	
RLM_MODULE_UPDATED = 8
RLM_MODULE_NUMCODES = 9


# from radiusd.h
L_DBG = 1
L_AUTH = 2
L_INFO = 3
L_ERR = 4
L_PROXY	= 5
L_CONS = 128

OP={       '{':2,   '}':3,   '(':4,   ')':5,   ',':6,   ';':7,  '+=':8,  '-=':9,  ':=':10,
  '=':11, '!=':12, '>=':13,  '>':14, '<=':15,  '<':16, '=~':17, '!~':18, '=*':19, '!*':20,
 '==':21 , '#':22 }

OP_TRY = (':=', '+=', '-=', '=' )

def resolve(*lines):
    tuples = []
    for line in lines:
	for op in OP_TRY:
	    arr = line.rsplit(op)
	    if len(arr)==2:
		tuples.append((str(arr[0].strip()),OP[op],str(arr[1].strip())))
		break
    return tuple(tuples)

# log function
def radlog(level, msg):
    import sys
    sys.stdout.write(msg + '\n')

    level = level


