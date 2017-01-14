#!/usr/bin/env bash

function show_help {
    echo "Usage: ${0#*/} -h | this help -o <onos source path> -t <onos docker tag> -p <onos package> -b | build onos package -u |update onos source"
    exit 1
}

OPTIND=1
onos_src_dir="$HOME/onos"
onos_tag="test/onos:clustertest"
onos_package=
onos_build=0
onos_update=0

while getopts "h?o:t:p:bu" opt; do
    case "$opt" in
        h|\?)
            show_help
            ;;
        o)
            onos_src_dir=$OPTARG
            ;;
        p)
            onos_package=$OPTARG
            ;;
        t)
            onos_tag=$OPTARG
            ;;
        b)
            onos_build=1
            ;;
        u)
            onos_update=1
            ;;
        *)
            show_help
            ;;
    esac
done

shift $((OPTIND-1))
if [ $# -gt 0 ]; then
    echo "Invalid arguments"
    show_help
fi
mydir=$(dirname $(realpath $0))
if [ x"$onos_package" = "x" ]; then
    if [ ! -d $onos_src_dir ]; then
        onos_build=1
    fi
    onos_package=$onos_src_dir/buck-out/gen/tools/package/onos-package/onos.tar.gz
fi

function build_onos {
    if [ ! -f $mydir/Dockerfile.onos-builder ]; then
        echo "Dockerfile.onos-builder not found. Copy this file from cord-tester project before resuming the build"
        exit 127
    fi
    docker images | grep ^cord-tester-onos-builder || docker build -t cord-tester-onos-builder:latest -f $mydir/Dockerfile.onos-builder $mydir
    docker run -v $mydir:/root/cord-tester --rm cord-tester-onos-builder:latest
    return $?
}

#if onos package is not built, then exit
if [ $onos_build -eq 1 ]; then
    if [ ! -d $onos_src_dir ]; then
        build_onos
        local ret=$?
        if [ $ret -ne 0 ]; then
            echo "Failed to build ONOS. Exiting"
            exit 127
        fi
        onos_package=$mydir/onos.tar.gz
    else
      if [ $onos_update -eq 1 ]; then
          echo "Updating ONOS source"
          ( cd $onos_src_dir && git pull --ff-only origin master || git clone http://github.com/opennetworkinglab/onos.git . )
      fi
      ( cd $onos_src_dir && tools/build/onos-buck build onos ) && echo "ONOS build success" || {
        echo "ONOS build failure. Exiting ..." && exit 1
      }
      onos_package=$onos_src_dir/buck-out/gen/tools/package/onos-package/onos.tar.gz
    fi
fi

if [ ! -f $onos_package ]; then
    echo "ONOS package $onos_package does not exist. Exiting ..."
    exit 1
fi

if [ $onos_package != $mydir/onos.tar.gz ]; then
    cp -v $onos_package $mydir/onos.tar.gz
fi

function finish {
    rm -f onos.tar.gz
    rm -f Dockerfile.cord-tester
}

trap finish EXIT

#create a ONOS docker file
cat > $mydir/Dockerfile.cord-tester <<EOF
FROM onosproject/onos:latest

MAINTAINER Ali Al-Shabibi <ali@onlab.us>

# Add Java 8 repository
# Set the environment variables
ENV HOME /root
ENV JAVA_HOME /usr/lib/jvm/java-8-oracle
ENV ONOS_ROOT /src/onos
ENV KARAF_VERSION 3.0.5
ENV KARAF_ROOT /root/onos/apache-karaf-3.0.5
ENV KARAF_LOG /root/onos/apache-karaf-3.0.5/data/log/karaf.log
ENV BUILD_NUMBER docker
ENV PATH \$PATH:\$KARAF_ROOT/bin

#Download and Build ONOS
# Change to /root directory
WORKDIR /root
COPY ./onos.tar.gz /tmp
#Install ONOS

RUN rm -rf onos && mkdir onos && \
   mv /tmp/onos.tar.gz . && \
   tar -xf onos.tar.gz -C onos --strip-components=1 && \
   rm -rf onos.tar.gz


# Ports
# 6653 - OpenFlow
# 8181 - GUI
# 8101 - ONOS CLI
# 9876 - ONOS CLUSTER COMMUNICATION
EXPOSE 6653 8181 8101 9876

# Get ready to run command
WORKDIR /root/onos
ENTRYPOINT ["./bin/onos-service"]
EOF

#Now build the docker image
docker build -t $onos_tag -f $mydir/Dockerfile.cord-tester $mydir
