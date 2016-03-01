#!/bin/bash
odir="$1"
if [ -z "$odir" ]; then
    odir = "./"
fi

##Generate TLS authentication Test state machine
python yamlFsm.py -p TlsAuthHolder -f noseTlsAuthTest.yaml > ${odir}/noseTlsAuthHolder.py

##Generate PAP authentication state machine
python yamlFsm.py -p PAPAuthHolder -f nosePAPTest.yaml > ${odir}/nosePAPAuthHolder.py


##Generate DNS test state machine
python yamlFsm.py -p DnsHolder -f noseDnsTest.yaml > ${odir}/noseDnsHolder.py

