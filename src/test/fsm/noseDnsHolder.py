#!/usr/bin/env python

def initDnsHolderFsmTable(obj,St,Ev):
    return {

    ## CurrentState                Event                            Actions               NextState

      (St.ST_DNS_SND_REC,          Ev.EVT_DNS_SND_REC           ):( (obj._dns_snd_rec,),  St.ST_DNS_FINAL),

}

