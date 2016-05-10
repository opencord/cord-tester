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
#!/usr/bin/env python

def initMd5AuthHolderFsmTable(obj,St,Ev):
    return {

    ## CurrentState                          Event                                      Actions                   NextState

      (St.ST_EAP_SETUP,                      Ev.EVT_EAP_SETUP                       ):( (obj._eapSetup,),         St.ST_EAP_START),

    ## CurrentState                          Event                                      Actions                   NextState

      (St.ST_EAP_MD5_CHALLENGE,              Ev.EVT_EAP_MD5_CHALLENGE               ):( (obj._eapMd5Challenge,),  St.ST_EAP_STATUS),

    ## CurrentState                          Event                                      Actions                   NextState

      (St.ST_EAP_STATUS,                     Ev.EVT_EAP_STATUS                      ):( (obj._eapStatus,),        St.ST_EAP_MD5_DONE),

    ## CurrentState                          Event                                      Actions                   NextState

      (St.ST_EAP_ID_REQ,                     Ev.EVT_EAP_ID_REQ                      ):( (obj._eapIdReq,),         St.ST_EAP_MD5_CHALLENGE),

    ## CurrentState                          Event                                      Actions                   NextState

      (St.ST_EAP_START,                      Ev.EVT_EAP_START                       ):( (obj._eapStart,),         St.ST_EAP_ID_REQ),

}

