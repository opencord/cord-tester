#!/usr/bin/env bash
json="$1"
controller="$2"
if [ x"$json" = "x" ]; then
  echo "No json file specified. Exiting"
  exit 127
fi
if [ x"$controller" = "x" ]; then
    controller=`ovs-vsctl show | egrep "Controller|tcp" | grep -v ptcp | sed 's,Controller,,g' | sed 's,\",,g' | tr -s ' '|awk -F":" '{print $2}'`
    #echo "Controller at $controller"
fi
#echo "Loading ssm translate json file $json to controller at $controller"
curl --fail -sSL --user karaf:karaf \
    -X POST -H 'Content-Type:application/json' \
    http://$controller:8181/onos/v1/network/configuration/ -d@$json


