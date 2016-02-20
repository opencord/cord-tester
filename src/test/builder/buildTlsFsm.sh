#!/bin/bash
odir="$1"
if [ -z "$odir" ]; then
    odir = "./"
fi
python yamlFsm.py -p TlsAuthHolder -f noseTlsAuthTest.yaml > ${odir}/noseTlsAuthHolder.py
