#!/usr/bin/env python

def initTlsAuthHolderFsmTable(obj,St,Ev):
    return {

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_TLS_HELLO_REQ,                       Ev.EVT_EAP_TLS_HELLO_REQ                        ):( (obj._eapTlsHelloReq,),          St.ST_EAP_TLS_CERT_REQ),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_ID_REQ,                              Ev.EVT_EAP_ID_REQ                               ):( (obj._eapIdReq,),                St.ST_EAP_TLS_HELLO_REQ),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_SETUP,                               Ev.EVT_EAP_SETUP                                ):( (obj._eapSetup,),                St.ST_EAP_START),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_TLS_FINISHED,                        Ev.EVT_EAP_TLS_FINISHED                         ):( (obj._eapTlsFinished,),          St.ST_EAP_TLS_DONE),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_START,                               Ev.EVT_EAP_START                                ):( (obj._eapStart,),                St.ST_EAP_ID_REQ),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_TLS_CHANGE_CIPHER_SPEC,              Ev.EVT_EAP_TLS_CHANGE_CIPHER_SPEC               ):( (obj._eapTlsChangeCipherSpec,),  St.ST_EAP_TLS_FINISHED),

    ## CurrentState                                   Event                                               Actions                          NextState

      (St.ST_EAP_TLS_CERT_REQ,                        Ev.EVT_EAP_TLS_CERT_REQ                         ):( (obj._eapTlsCertReq,),           St.ST_EAP_TLS_CHANGE_CIPHER_SPEC),

}

