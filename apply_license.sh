#!/usr/bin/env bash
for f in `find . -name "*.py"`; do
    if ! grep -q Copyright $f; then
        cat COPYRIGHT.txt $f > $f.license.py
        mv $f.license.py $f
        #prepend shebang for python
        sed -i -e '/^\#\!\/usr\/bin/d' -e '1i\#\!/usr/bin/env python' $f
        chmod +x $f
    fi
done
