#!/usr/bin/env python

def initTlsAuthHolderFsmTable(obj,St,Ev):
    return {

    ## CurrentState                          Event                                      Actions                  NextState

      (St.ST_EAP_SETUP,                      Ev.EVT_EAP_SETUP                       ):( (obj._eapSetup,),        St.ST_EAP_START),

    ## CurrentState                          Event                                      Actions                  NextState

      (St.ST_EAP_TLS_HELLO_REQ,              Ev.EVT_EAP_TLS_HELLO_REQ               ):( (obj._eapTlsHelloReq,),  St.ST_EAP_TLS_CERT_REQ),

    ## CurrentState                          Event                                      Actions                  NextState

      (St.ST_EAP_START,                      Ev.EVT_EAP_START                       ):( (obj._eapStart,),        St.ST_EAP_ID_REQ),

    ## CurrentState                          Event                                      Actions                  NextState

      (St.ST_EAP_ID_REQ,                     Ev.EVT_EAP_ID_REQ                      ):( (obj._eapIdReq,),        St.ST_EAP_TLS_HELLO_REQ),

    ## CurrentState                          Event                                      Actions                  NextState

      (St.ST_EAP_TLS_CERT_REQ,               Ev.EVT_EAP_TLS_CERT_REQ                ):( (obj._eapTlsCertReq,),   St.ST_EAP_TLS_DONE),

}

