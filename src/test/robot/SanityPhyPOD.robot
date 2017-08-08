
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
@{MAAS_SERVICE_STATUS}    start/running    is running
@{JUJU_SERVICE_STATUS}    active           is ready
@{LXD_CONTAINER_STATUS}   RUNNING
@{BOOT_RESOURCES_OUTPUT}  ubuntu/trusty
${FABRIC_SWITCH_PROMPT}    #
${FABRIC_SWITCH_USER}     root
${FABRIC_SWITCH_PASSWD}    onl
@{FABRIC_SERVICE_STATUS}    is running
${IP_PATTERN}     (\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)

*** Test Cases ***
Verify headnode interfaces detected
    Verify HeadNode Interfaces

Verify the state MAAS service
    [Template]     Verify MAAS Service
    maas-dhcpd
    maas-regiond
    maas-clusterd
    maas-proxy
    bind9

Verify the state of MAAS Containers
    [Template]      Verify Containers   
    cord-maas-automation    
    cord-maas-switchq    
    cord-provisioner    
    cord-ip-allocator    
    cord-dhcp-harvester
    config-generator    

Verify the state of XOS Containers
    [Template]      Verify Containers   
    xos-gui    
    xos-ws    
    chameleon    
    xos-ui
    onos-synchronizer
    vrouter-synchronizer
    exampleservice-synchronizer
    vsg-synchronizer    
    gui-extension-rcord
    gui-extension-vtr
    vtn-synchronizer
    vtr-synchronizer
    fabric-synchronizer
    openstack-synchronizer
    xos-postgres

Verify the state of ONOS Containers
    [Template]      Verify Containers   
    onosproject/onos
    xos/onos
 
Verify the state of other Containers
    [Template]      Verify Containers   
    redis 
    mavenrepo
    registry-mirror
    registry

Verify the state of juju services
    [Template]    Verify JUJU Service
    ceilometer
    ceilometer-agent
    glance
    keystone
    mongodb
    nagios
    neturon-api
    nova-cloud-controller
    nova-compute
    openstack-dashboard
    percona-cluster
    rabbitmq-server

Verify the state of openstack lxd containers
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
    Verify MAAS CLI Commands   devices list | jq '.' | jq '.[]'.hostname | wc -l     3 
    #Verify MAAS CLI Commands   events query | jq '.' | jq .events[].id | wc -l    100 
    Verify MAAS CLI Commands   fabrics read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   networks read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   node-groups list | jq '.' | jq .[].status | wc -l    1
    Verify MAAS CLI Commands   subnets read | jq '.' | jq .[].name | wc -l    4
    Verify MAAS CLI Commands   nodes list | jq '.' | jq .[].substatus_name | wc -l    1
    Verify MAAS CLI Commands   zones read | jq '.' | jq .[].name | wc -l   2 
    Logout MAAS Server

Verify Fabric Switch Service
    ${fabric_ip}=    Discover FABRIC IP    ${FABRIC_SWITCH_MAC}   
    Verify Fabric Switch Service    ${fabric_ip}    faultd
    Verify Fabric Switch Service    ${fabric_ip}    netplug 
    Verify Fabric Switch Service    ${fabric_ip}    ofdpa
    Verify Fabric Switch Service    ${fabric_ip}    onlp-snmpd
    Verify Fabric Switch Service    ${fabric_ip}    onlpd
    Verify Fabric Switch Service    ${fabric_ip}    resolvconf 
    Verify Fabric Switch Service    ${fabric_ip}    rsyslog
    Verify Fabric Switch Service    ${fabric_ip}    snmpd 
    Verify Fabric Switch Service    ${fabric_ip}    ssh 
    Verify Fabric Switch Service    ${fabric_ip}    sxdkernel 
    Verify Fabric Switch Service    ${fabric_ip}    udev 
    Verify Fabric Switch Service    ${fabric_ip}    watchdog 


*** Keywords ***
Verify HeadNode Interfaces
    ${cmd}=    Catenate    SEPARATOR=|   sudo ethtool mgmtbr    grep 'Link detected:'    awk '{ print $3 }'
    ${output}=    Run     ${cmd} 
    Should Contain    ${output}    yes    msg= mgmtbr is not detected !!!. Reason:
    ${cmd}=    Catenate    SEPARATOR=|   sudo ethtool fabric    grep 'Link detected:'    awk '{ print $3 }'
    ${output}=    Run     ${cmd} 
    Should Contain    ${output}    yes    msg= fabric interface is not detected !!!. Reason:


Verify Containers 
    [Arguments]    ${name} 
    ${cmd}=    Catenate    SEPARATOR=|   docker ps -a  grep -v grep  grep ${name}    awk '{print $7,$8,$9,$10,$11}'     
    ${output}=    Run     ${cmd} 
    Should Contain    ${output}    Up    msg= ${name} is not running !!!. Reason:

Verify MAAS Service
    [Arguments]    ${name}
    ${cmd}=    Catenate   sudo service    ${name}   status 
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

Discover FABRIC IP
    [Arguments]    ${fabric_mac}
    ${cmd}   Catenate    SEPARATOR=|  cord switch list   grep -v IP   awk '{ print $3 }' 
    ${output}=    Run     ${cmd} 
    ${ret}=    Should Match Regexp    ${output}    ${IP_PATTERN}    msg="unable to get ip"   
    [Return]   ${ret[0]} 

Verify Fabric Switch Service
    [Arguments]    ${ip}    ${name}
    ${cmd}=    Catenate    service   ${name}   status 
    ${output}=    Run Command On Remote System    ${ip}    ${cmd}   ${FABRIC_SWITCH_USER}   ${FABRIC_SWITCH_PASSWD}    ${FABRIC_SWITCH_PROMPT}   60s   False 
    Should Contain Any    ${output}    @{FABRIC_SERVICE_STATUS}    msg= ${name} is not running !!!. Reason:
