#!/usr/bin/env python

def initPAPAuthHolderFsmTable(obj,St,Ev):
    return {

    ## CurrentState                           Event                                       Actions                 NextState

      (St.ST_EAP_SETUP,                       Ev.EVT_EAP_SETUP                        ):( (obj._eapSetup,),       St.ST_EAP_START),

    ## CurrentState                           Event                                       Actions                 NextState

      (St.ST_EAP_PAP_PASSWD_REQ,              Ev.EVT_EAP_PAP_PASSWD_REQ               ):( (obj._eapPAPPassReq,),  St.ST_EAP_PAP_DONE),

    ## CurrentState                           Event                                       Actions                 NextState

      (St.ST_EAP_PAP_USER_REQ,                Ev.EVT_EAP_PAP_USER_REQ                 ):( (obj._eapPAPUserReq,),  St.ST_EAP_PAP_PASSWD_REQ),

    ## CurrentState                           Event                                       Actions                 NextState

      (St.ST_EAP_ID_REQ,                      Ev.EVT_EAP_ID_REQ                       ):( (obj._eapIdReq,),       St.ST_EAP_PAP_USER_REQ),

    ## CurrentState                           Event                                       Actions                 NextState

      (St.ST_EAP_START,                       Ev.EVT_EAP_START                        ):( (obj._eapStart,),       St.ST_EAP_ID_REQ),

}

