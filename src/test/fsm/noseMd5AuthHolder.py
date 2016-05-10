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

