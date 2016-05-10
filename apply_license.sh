#!/usr/bin/env bash
for f in `find . -name "*.py"`; do
    if ! grep -q Copyright $f; then
        cat COPYRIGHT.txt $f > $f.license.py
        mv $f.license.py $f
    fi
done