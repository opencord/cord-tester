
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
Library       OperatingSystem
Resource      ../cord-api/Framework/utils/utils.robot

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
${public_iface}               eth2
${num_of_switches}            4

*** Test Cases ***
Verify Headnode Interfaces
    Verify HeadNode Interfaces Detected
    Test Ping    ${public_iface}    8.8.8.8

Verify Compute Nodes Pingability
    [Documentation]    Verifies that the two compute nodes can ping each other and the headnode
    [Tags]    pod1
    ##Get compute node information
    ${compute_node1_hostname}=    Run    cord prov list | grep node | awk '{print $2}' | sed -n 1p
    ${compute_node2_hostname}=    Run    cord prov list | grep node | awk '{print $2}' | sed -n 2p
    ${compute_node1_hostname_prefix}=    Remove String    ${compute_node1_hostname}    .cord.lab
    ${compute_node2_hostname_prefix}=    Remove String    ${compute_node2_hostname}    .cord.lab
    ${compute_node1_ip}=    Run    cord harvest list | grep ${compute_node1_hostname_prefix} | awk '{print $4}'
    ${compute_node2_ip}=    Run    cord harvest list | grep ${compute_node2_hostname_prefix} | awk '{print $4}'
    ${result1}=    Run    ssh -A ubuntu@${compute_node1_hostname} "ping -c 5 ${compute_node2_hostname}"
    ${result2}=    Run    ssh -A ubuntu@${compute_node2_hostname} "ping -c 5 ${compute_node1_hostname}"
    Should Contain    ${result1}    64 bytes
    Should Not Contain    ${result1}    Destination Host Unreachable
    Should Contain    ${result2}    64 bytes
    Should Not Contain    ${result2}    Destination Host Unreachable
    Set Suite Variable    ${compute_node1_hostname}
    Set Suite Variable    ${compute_node2_hostname}
    Set Suite Variable    ${compute_node1_hostname_prefix}
    Set Suite Variable    ${compute_node2_hostname_prefix}
    Set Suite Variable    ${compute_node1_ip}
    Set Suite Variable    ${compute_node2_ip}

Verify CordVTN Nodes
    [Documentation]    Verifies that the cordvtn app running in onos identifies the nodes and devices (fabric)
    ${nodes}=    Execute ONOS Command    onos-cord    8102    cordvtn-nodes
    ${node_1}=    Get Lines Containing String    ${nodes}    ${compute_node1_ip}
    Should Contain    ${node_1}    COMPLETE
    Should Contain    ${node_1}    ${compute_node1_ip}
    ${node_2}=    Get Lines Containing String    ${nodes}    ${compute_node2_ip}
    Should Contain    ${node_2}    COMPLETE
    Should Contain    ${node_2}    ${compute_node2_ip}
    ${ports}=    Execute ONOS Command    onos-cord    8102    cordvtn-ports
    ${devices}=    Execute ONOS Command    onos-cord    8102    devices
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

Verify MAAS Containers State
    [Template]      Verify Containers   
    maas-automation
    maas-switchq
    maas-provisioner
    maas-allocator
    maas-harvester
    maas-generator

Verify XOS Containers State
    [Template]      Verify Containers   
    xos-gui    
    xos-ws    
    chameleon    
    xos-ui
    onos-synchronizer
    vrouter-synchronizer
    exampleservice-synchronizer
    vsg-synchronizer    
    vtn-synchronizer
    vtr-synchronizer
    fabric-synchronizer
    openstack-synchronizer
    xos-postgres

Verify ONOS Containers State
    [Template]      Verify Containers   
    onosproject/onos
    xos/onos
 
Verify Other Containers State
    [Template]      Verify Containers   
    redis 
    mavenrepo
    registry-mirror

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
    #testclient

Verify MAAS CLI commands
    Login MAAS Server
    Verify MAAS CLI Commands   boot-resources read | jq 'map(select(.type == "Synced"))'    ubuntu/trusty
    Verify MAAS CLI Commands   devices list | jq '.' | jq '.[]'.hostname | wc -l     ${num_of_switches}
    #Verify MAAS CLI Commands   events query | jq '.' | jq .events[].id | wc -l    100 
    Verify MAAS CLI Commands   fabrics read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   networks read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   node-groups list | jq '.' | jq .[].status | wc -l    1
    Verify MAAS CLI Commands   subnets read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   nodes list | jq '.' | jq .[].substatus_name | wc -l    1
    Verify MAAS CLI Commands   zones read | jq '.' | jq .[].name | wc -l   2 
    Logout MAAS Server

Verify Fabric Switch Service
    @{switch_ips}=    Discover FABRIC IPs
    : FOR    ${i}    IN    @{switch_ips}
    \    Verify Fabric Switch Service    ${i}    faultd
    \    Verify Fabric Switch Service    ${i}    netplug
    \    Verify Fabric Switch Service    ${i}    ofdpa
    \    Verify Fabric Switch Service    ${i}    onlp-snmpd
    \    Verify Fabric Switch Service    ${i}    onlpd
    \    Verify Fabric Switch Service    ${i}    resolvconf
    \    Verify Fabric Switch Service    ${i}    rsyslog
    \    Verify Fabric Switch Service    ${i}    snmpd
    \    Verify Fabric Switch Service    ${i}    ssh
    \    Verify Fabric Switch Service    ${i}    sxdkernel
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
