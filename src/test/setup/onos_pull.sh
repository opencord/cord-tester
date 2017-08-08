
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


#!/usr/bin/env bash
##Use this script as SUDO to pull ONOS safely as it saves/archives repo digest ids.
##Repo digest ids are saved in $HOME/onos_repo_digest.txt
tag=${1:-latest}
repo_digest="$HOME/onos_repo_digest.txt"
echo "Pulling ONOS $tag"
digest=`docker pull onosproject/onos:$tag | grep Digest`
echo "Got $digest for ONOS $tag"
repo=`echo $digest | cut -d ":" -f2- | sed 's,[[:space:]]*,,'`
echo "ONOS $tag repo id $repo saved in $repo_digest"
d=`date +%D`
echo "$d onosproject/onos:$tag $repo" >>$repo_digest