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