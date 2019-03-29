#!/bin/bash

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
