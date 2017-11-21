# Copyright 2017-present Radisys Corporation
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


*** Settings ***
Documentation     Test suite for checking default maas,xos and onos containers and fabric switch default services and maas cli commands
Library           OperatingSystem
Library           ../cord-api/Framework/utils/onosUtils.py
Library           ../cord-api/Framework/utils/utils.py
Resource          ../cord-api/Framework/utils/utils.robot

*** Variables ***
@{MAAS_SERVICE_STATUS}        start/running    is running
@{JUJU_SERVICE_STATUS}        active           is ready    unknown
@{LXD_CONTAINER_STATUS}       RUNNING
@{BOOT_RESOURCES_OUTPUT}      ubuntu/trusty
${FABRIC_SWITCH_PROMPT}       \#
${FABRIC_SWITCH_USER}         root
${FABRIC_SWITCH_PASSWD}       onl
@{FABRIC_SERVICE_STATUS}      is running
${IP_PATTERN}                 (\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)
${PUBLIC_IFACE}               eth2
${NUM_OF_SWITCHES}            4
${CORD_PROFILE}               rcord
${FABRIC}                     on
${DOCKER_CONTAINERS_FILE}     ${CURDIR}/../diag/dockerContainers.json

*** Test Cases ***
Verify Headnode Interfaces
    [Tags]    fabric
    [Documentation]    Verifies the headnode interface is up and has external connectivity
    Verify HeadNode Interfaces Detected
    Test Ping    ${PUBLIC_IFACE}    www.opennetworking.org

Get Compute Node and Fabric Info
    [Documentation]    Get all information pretaining to the compute nodes and fabric
    ${nodes}=    Create List
    ${hostnames}=    Create List
    ${hostname_prefixes}=    Create List
    ${node_ips}=    Create List
    ${node_data_ips}=    Create List
    ${node_count}    Run    cord prov list | grep node | wc -l
    ${node_count}=    Convert To Integer    ${node_count}
    Log    ${node_count}
    ##Get hostname
    : FOR    ${INDEX}    IN RANGE    1    ${node_count}+1
    \    ${hostname}=    Run    cord prov list | grep node | awk '{print $2}' | sed -n ${INDEX}p
    \    Append To List    ${hostnames}    ${hostname}
    ##Get hostname prefixes
    : FOR    ${INDEX}    IN RANGE    0    ${node_count}
    \    ${hostname_prefix}=    Remove String    ${hostnames[${INDEX}]}    .cord.lab
    \    Append To List    ${hostname_prefixes}    ${hostname_prefix}
    ##Get compute node data ips
    ${cordvtnnodes}=    ONOS Command Execute    onos-cord    8102    cordvtn-nodes | grep fabric
    ${nds}=    Split To Lines    ${cordvtnnodes}
    : FOR    ${i}    IN    @{nds}
    \    ${data_ip}=    Get Compute Node IP    ${i}
    \    Append To List    ${node_data_ips}    ${data_ip}
    ##Get compute node ips
    : FOR    ${i}    IN    @{hostname_prefixes}
    \    ${node_ip}=    Run    cord harvest list | grep ${i} | awk '{print $4}'
    \    Append To List    ${node_ips}    ${node_ip}
    @{switch_ips}=    Discover FABRIC IPs
    Set Suite Variable    ${switch_ips}
    Set Suite Variable    ${hostnames}
    Set Suite Variable    ${hostname_prefixes}
    Set Suite Variable    ${node_ips}
    Set Suite Variable    ${node_data_ips}

Verify Compute Nodes Pingability Through Fabric
    [Documentation]    Verifies that the two compute nodes can ping each other through the fabric
    [Tags]    fabric
    ##Verify pingablilty across compute nodes
    : FOR    ${src}    IN    @{hostname_prefixes}
    \    Ping All Compute Nodes Through Fabric    ${src}

Verify Compute Nodes to Fabric Pingability
    [Documentation]    Verifies that the two compute nodes can ping the switches
    [Tags]    fabric
    ##Verify pingability from compute nodes to fabric
    : FOR    ${src}    IN    @{hostname_prefixes}
    \    Ping All Fabric Switches    ${src}

Verify CordVTN Nodes
    [Documentation]    Verifies that the cordvtn app running in onos identifies the nodes and devices (fabric)
    ${nodes}=    Execute ONOS Command    onos-cord    8102    cordvtn-nodes
    : FOR    ${i}    IN    @{node_ips}
    \    ${node_1}=    Get Lines Containing String    ${nodes}    ${i}
    \    Run Keyword If    "${FABRIC}" == "on"    Verify CordVTN Node    ${node_1}    COMPLETE    ${i}
    \    Run Keyword If    "${FABRIC}" == "off"    Verify CordVTN Node    ${node_1}    DEVICE_CREATED    ${i}
    ${ports}=    Execute ONOS Command    onos-cord    8102    cordvtn-ports
    ${devices}=    Execute ONOS Command    onos-fabric    8101    devices
    @{switch_ips}=    Discover FABRIC IPs
    : FOR    ${i}    IN    @{switch_ips}
    \    Should Contain    ${devices}    ${i}

Verify MAAS Service State
    [Template]     Verify MAAS Service
    maas-dhcpd
    maas-regiond
    maas-clusterd
    maas-proxy
    bind9

Verify Docker Containers State
    ${dockerContainers}    utils.jsonToList    ${DOCKER_CONTAINERS_FILE}    docker-containers-${CORD_PROFILE}
    : FOR    ${container}    IN    @{dockerContainers}
    \    Verify Containers    ${container}

Verify Juju Services State
    [Template]    Verify JUJU Service
    ceilometer
    ceilometer-agent
    glance
    keystone
    mongodb
    nagios
    neutron-api
    nova-cloud-controller
    nova-compute
    openstack-dashboard
    percona-cluster
    rabbitmq-server

Verify Openstack LXD Containers State
    [Template]    Verify Openstack LXD Containers
    ceilometer
    glance
    keystone
    mongodb
    nagios
    neutron-api
    nova-cloud-controller
    openstack-dashboard
    percona-cluster
    rabbitmq-server

Verify MAAS CLI commands
    [Tags]    notready
    Login MAAS Server
    Verify MAAS CLI Commands   boot-resources read | jq 'map(select(.type == "Synced"))'    ubuntu/trusty
    Verify MAAS CLI Commands   devices list | jq '.' | jq '.[]'.hostname | wc -l     ${NUM_OF_SWITCHES}
    #Verify MAAS CLI Commands   events query | jq '.' | jq .events[].id | wc -l    100
    Verify MAAS CLI Commands   fabrics read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   networks read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   node-groups list | jq '.' | jq .[].status | wc -l    1
    Verify MAAS CLI Commands   subnets read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   nodes list | jq '.' | jq .[].substatus_name | wc -l    1
    Verify MAAS CLI Commands   zones read | jq '.' | jq .[].name | wc -l   2
    Logout MAAS Server

Verify Fabric Switch Service
    [Tags]    fabric
    @{switch_ips}=    Discover FABRIC IPs
    : FOR    ${i}    IN    @{switch_ips}
    \    Verify Fabric Switch Service    ${i}    faultd
    \    Verify Fabric Switch Service    ${i}    netplug
    \    Verify Fabric Switch Service    ${i}    onlp-snmpd
    \    Verify Fabric Switch Service    ${i}    onlpd
    \    Verify Fabric Switch Service    ${i}    rsyslog
    \    Verify Fabric Switch Service    ${i}    snmpd
    \    Verify Fabric Switch Service    ${i}    ssh
    \    Verify Fabric Switch Service    ${i}    udev
    \    Verify Fabric Switch Service    ${i}    watchdog

*** Keywords ***
Verify HeadNode Interfaces Detected
    ${cmd}=    Catenate    SEPARATOR=|   sudo ethtool mgmtbr    grep 'Link detected:'    awk '{ print $3 }'
    ${output}=    Run     ${cmd}
    Should Contain    ${output}    yes    msg= mgmtbr is not detected !!!. Reason:
    ${cmd}=    Catenate    SEPARATOR=|   sudo ethtool fabric    grep 'Link detected:'    awk '{ print $3 }'
    ${output}=    Run     ${cmd}
    Should Contain    ${output}    yes    msg= fabric interface is not detected !!!. Reason:

Verify CordVTN Node
    [Arguments]    ${node}    ${status}    ${ip}
    Should Contain    ${node}    ${status}
    Should Contain    ${node}    ${ip}

Verify Containers
    [Arguments]    ${name}
    ${container_id}=    Get Docker Container ID    ${name}
    ${output}=    Run     docker inspect --format="{{ .State.Running }}" ${container_id}
    Should Contain    ${output}    true    msg=${name} is not running !!!. Reason:

Verify MAAS Service
    [Arguments]    ${name}
    ${cmd}=    Catenate   sudo service ${name} status
    ${output}=    Run     ${cmd}
    Should Contain Any    ${output}    @{MAAS_SERVICE_STATUS}    msg= ${name} is not running !!!. Reason:

Verify JUJU Service
    [Arguments]    ${name}
    ${cmd}    Catenate    SEPARATOR=|    juju status --format=tabular    grep -v grep    grep ${name}/0    awk '{ print $2,$7,$8,$9,$10}'
    ${output}=    Run     ${cmd}
    Should Contain Any    ${output}    @{JUJU_SERVICE_STATUS}    msg= ${name} is not running !!!. Reason:

Verify Openstack LXD Containers
    [Arguments]    ${name}
    ${cmd}    Catenate    SEPARATOR=|    sudo lxc list    grep -v grep    grep ${name}-1    awk '{ print $2,$4 }'
    ${output}=    Run     ${cmd}
    Should Contain Any    ${output}    @{LXD_CONTAINER_STATUS}    msg= ${name} is not running !!!. Reason:

Verify MAAS CLI Commands
    [Arguments]    ${name}    ${expected}
    ${cmd}    Catenate    maas cord ${name}
    ${output}=    Run     ${cmd}
    Should Contain    ${output}    ${expected}    msg=Reason:

Login MAAS Server
    ${cmd}   Catenate   maas login cord http://localhost/MAAS/api/1.0 $(sudo maas-region-admin apikey --user=cord)
    ${output}=    Run     ${cmd}
    Should Contain   ${output}   You are now logged in to the MAAS  msg= MAAS login failure !!!. Reason:

Logout MAAS Server
    ${cmd}   Catenate   maas logout cord
    ${output}=    Run     ${cmd}

Discover FABRIC IPs
    ${switches}=    Run    cord prov list | grep fabric | awk '{print $4}'
    @{switch_ips}=    Split To Lines    ${switches}
    [Return]    ${switch_ips}

Verify Fabric Switch Service
    [Arguments]    ${ip}    ${name}
    ${cmd}=    Catenate    service   ${name}   status
    ${output}=    Run Command On Remote System    ${ip}    ${cmd}   ${FABRIC_SWITCH_USER}   ${FABRIC_SWITCH_PASSWD}    ${FABRIC_SWITCH_PROMPT}   60s   False
    Should Contain Any    ${output}    @{FABRIC_SERVICE_STATUS}    msg= ${name} is not running !!!. Reason:

Ping All Compute Nodes Through Fabric
    [Arguments]    ${src_ip}
    : FOR    ${dst_ip}    IN    @{node_data_ips}
    \    Verify Ping    ubuntu    ${src_ip}    ${dst_ip}

Ping All Fabric Switches
    [Arguments]    ${src_ip}
    : FOR    ${dst_ip}    IN    @{switch_ips}
    \    Verify Ping    ubuntu    ${src_ip}    ${dst_ip}

Verify Ping
    [Arguments]    ${srcName}    ${srcIP}    ${dst}
    ${result}=    Run    ssh ${srcName}@${srcIP} "ping -c 3 ${dst}"
    Should Contain    ${result}    64 bytes
    Should Not Contain    ${result}    Destination Host Unreachable
