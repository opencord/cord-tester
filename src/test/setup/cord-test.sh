#!/usr/bin/env bash

function show_help {
    echo "Usage: ${0#*/} -h | this help -n <onos_ip> -r <radius_ip> -o <onos cnt image> -a < onos app file> -d <radius cnt image> -t <test type> -c | cleanup test containers -C <cleanup container list> -k | kill the test container -b <test cnt image> | build test container docker image"
    exit 1
}

function cnt_ipaddr {
    local image="${1}"
    local cnt=`docker ps |grep "${image}" |awk '{print $1}'`
    local ipaddr
    ipaddr=`docker inspect -f '{{.NetworkSettings.IPAddress}}' $cnt`
    echo $ipaddr
}

function onos_start {
    local image="${1}"
    local port_str=""
    for p in 8181 8101 9876 6653 6633; do
        port_str="$port_str -p $p:$p/tcp"
    done
    ONOS_APPS="drivers,openflow,proxyarp,mobility,fwd,aaa,igmp"
    local cnt=`docker run -itd $port_str -e ONOS_APPS=${ONOS_APPS} $image /bin/bash`
    local ipaddr
    ipaddr=`docker inspect -f '{{.NetworkSettings.IPAddress}}' $cnt`
    echo $ipaddr
}

test_type=dhcp
onos_cnt_image=onosproject/onos
radius_cnt_image=radius-server:dev
onos_ip=
radius_ip=
OPTIND=1
nose_cnt_image="onos:nosetest"
cleanup=0
kill_test_cnt=0
build_cnt_image=
cleanup_cnt_list=
app_version=1.0-SNAPSHOT
onos_app_file=$PWD/../apps/ciena-cordigmp-$app_version.oar

while getopts "h?a:n:r:o:d:t:cC:kb:" opt; do 
    case "$opt" in
        h|\?)
            show_help
            exit 1
            ;;
        t)
            test_type=$OPTARG
            ;;
        n)
            onos_ip=$OPTARG
            ;;
        r)
            radius_ip=$OPTARG
            ;;
        o)
            onos_cnt_image=$OPTARG
            ;;
        d)
            radius_cnt_image=$OPTARG
            ;;
        a)
            onos_app_file=$OPTARG
            ;;
        c)
            cleanup=1
            ;;
        C)
            cleanup=1
            cleanup_cnt_list=$OPTARG
            ;;
        k)
            kill_test_cnt=1
            ;;
        b)
            build_cnt_image=$OPTARG
            ;;
    esac
done

shift $(($OPTIND-1))

if [ $# -gt 0 ]; then
    echo "Invalid args"
    show_help
fi

if [ $cleanup -eq 1 ]; then
    if [ x"$cleanup_cnt_list" != "x" ]; then
        IFS='-' read -r -a cleanup_list <<<"${cleanup_cnt_list}"
        for container in "${cleanup_list[@]}"; do
            cnt_id=`docker ps | grep "${container}" | awk '{print $1}'`
            echo "Killing container $cnt_id"
            docker kill $cnt_id
        done
        exit 0
    fi
    for container in `docker ps | grep "${nose_cnt_image}" | awk '{print $1}'`; do
        echo "Killing test container $container"
        docker kill $container
    done
    exit 0
fi

if [ x"$onos_ip" = "x" ]; then
    ##First try fetching the existing ip for onos container
    onos_ip=$(cnt_ipaddr $onos_cnt_image)
    ##If we find no onos running, then spawn the container if we can
    if [ x"$onos_ip" = "x" ]; then
        ##If the container image is from onosproject, we can try starting it
        if [[ "$onos_cnt_image" =~ "onosproject/" ]]; then
            echo "Starting ONOS container $onos_cnt_image"
            onos_ip=$(onos_start $onos_cnt_image)
            echo "Waiting 60 seconds for ONOS to fully boot up"
            sleep 60
        fi
    fi
fi

if [ x"$onos_ip" = "x" ]; then
    echo "ONOS not running or container name is invalid"
    exit 127
fi

if [ x"$radius_ip" = "x" ]; then
    radius_ip=$(cnt_ipaddr $radius_cnt_image)
fi

echo "Onos IP $onos_ip, Radius IP $radius_ip, Test type $test_type"
sed "s,%%CONTROLLER%%,$onos_ip,g" of-bridge-template.sh > $HOME/nose_exp/of-bridge.sh

if [ x"$build_cnt_image" != "x" ]; then
    echo "Building test container docker image $build_cnt_image"
    (cd test_docker && docker build -t $build_cnt_image . )
    sleep 2
    echo "Done building docker image $build_cnt_image"
    nose_cnt_image=$build_cnt_image
fi

function install_onos_app {
    local app=$1
    local onos_url="http://$onos_ip:8181/onos/v1/applications"
    local curl="curl -sS --user karaf:karaf"
    $curl -X POST -HContent-Type:application/octet-stream $onos_url?activate=true --data-binary @$app
}

echo "Installing and activating onos app $onos_app_file"

install_onos_app $onos_app_file

echo "Starting test container $nose_cnt_image"

test_cnt=`docker run -itd --privileged -v $HOME/nose_exp:/root/test -v /lib/modules:/lib/modules -e ONOS_CONTROLLER_IP=$onos_ip -e ONOS_AAA_IP=$radius_ip $nose_cnt_image /bin/bash`
echo "Setting up test container $test_cnt"
docker exec $test_cnt pip install monotonic
echo "Starting up the OVS switch on the test container $test_cnt"
docker exec $test_cnt /root/test/of-bridge.sh br0
status=0
while [ $status -ne 0 ]; do
    echo "Waiting for the switch to get connected to controller"
    docker exec $test_cnt ovs-ofctl dump-flows br0  | grep "type=0x8942"
    status=$?
    sleep 1
done
sleep 5

IFS='-' read -r -a tests <<<"${test_type}"
for t in "${tests[@]}"; do
    test_method="${t#*:}"
    test="${t%%:*}"
    case "$test" in
        tls)
            test_file="$test"AuthTest.py
            ;;
        *)
            test_file="$test"Test.py
            ;;
    esac
    if [ "$test_method" != "$t" ]; then
        test_case="$test_file":"${test_method}"
    else
        test_case="$test_file"
    fi
    echo "Running test $test, test case $test_case"
    docker exec $test_cnt nosetests -v /root/test/git/cord-tester/src/test/$test/"${test_case}"
    echo "Test $t exited with status $?"
done

echo "Done running tests."

if [ $kill_test_cnt -eq 1 ]; then
    echo "Killing test container $test_cnt"
    docker kill $test_cnt
fi

