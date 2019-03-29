#!/usr/bin/env bash

# Copyright 2017-present Open Networking Foundation
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

set -e

# to generate a patch:
#    pushd $SES_DIR && diff -c xos/synchronizer/models/simpleexampleservice.orig xos/synchronizer/models/simpleexampleservice.xproto > /tmp/migration-test.patch && popd

export PATCH_DIR=`pwd`
export REPO_DIR=/home/smbaker/projects/opencord/
export SES_DIR=$REPO_DIR/orchestration/xos-services/simpleexampleservice
export SES_MODELS_DIR=$SES_DIR/xos/synchronizer/models
export SES_MIG_DIR=$SES_DIR/xos/synchronizer/migrations

if [ ! -f $SES_MODELS_DIR/simpleexampleservice.orig ]; then
    cp $SES_MODELS_DIR/simpleexampleservice.xproto $SES_MODELS_DIR/simpleexampleservice.orig
fi

cd $SES_DIR

# migration-test1: initial image with no new files
rm -rf $SES_MIG_DIR/*.py
rm -rf $SES_MIG_DIR/*.pyc
xos-migrate -r $REPO_DIR -s simpleexampleservice --verbose

# In case we're pointing to a migration that's in an xos core that isn't released
sed -i 's/0009_auto_20190313_1442/0002_initial_data/g' $SES_MIG_DIR/0001_initial.py

docker build -t xosproject/simpleexampleservice-synchronizer:migration-test1 -f Dockerfile.synchronizer .

# migration-test2: new field added
#    required string new_field = 3 [
#        help_text = "New field to test data migration",
#        db_index = False,
#        default = "new_stuff"];

patch -d $SES_DIR -i $PATCH_DIR/migration-test2.patch -p0 -o xos/synchronizer/models/simpleexampleservice.xproto
xos-migrate -r $REPO_DIR -s simpleexampleservice --verbose
docker build -t xosproject/simpleexampleservice-synchronizer:migration-test2 -f Dockerfile.synchronizer .

# migration-test3: new field renamed
#    required string renamed_new_field = 3 [
#        help_text = "New field to test data migration",
#        db_index = False,
#        default = "renamed_new_stuff"];

patch -d $SES_DIR -i $PATCH_DIR/migration-test3.patch -p0 -o xos/synchronizer/models/simpleexampleservice.xproto
xos-migrate -r $REPO_DIR -s simpleexampleservice --verbose

echo "Generated migration script is likely incorrect -- manually edit and change it to a rename"
echo "   migrations.RenameField(model_name='simpleexampleservice', old_name='new_field', new_name='renamed_new_field'),"
read -n1 -r -p "Press any key and I will launch an editor..." key
emacs $SES_MIG_DIR/0003*.py

docker build -t xosproject/simpleexampleservice-synchronizer:migration-test3 -f Dockerfile.synchronizer .

# migration-test4: revert back to original models
cp $SES_MODELS_DIR/simpleexampleservice.orig $SES_MODELS_DIR/simpleexampleservice.xproto
xos-migrate -r $REPO_DIR -s simpleexampleservice --verbose
docker build -t xosproject/simpleexampleservice-synchronizer:migration-test4 -f Dockerfile.synchronizer .
