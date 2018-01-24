# Copyright 2018-present Open Networking Foundation
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
Test Timeout      2 minutes
Documentation     Validates external connectivity from Cord-Tester Container through VSG Subscriber
Library           OperatingSystem
Library           SSHLibrary
Library           /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/utils.py
Library           /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/onosUtils.py
Library           /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/openstackUtils.py
Resource          /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/utils.robot

*** Variables ***
${netcfg_file}    qct_fabric_test_netcfg.json

*** Test Cases ***
Configure X-Connects for 3 Subscribers
    [Documentation]    Configures the cross connect on the fabric switch with s-tags for the subscribers created via control-plane tests  on the correct ports
    ${netcfg_init}=    onosUtils.onos_command_execute    onos-fabric    8101    netcfg
    Log    ${netcfg_init}
    Run    http -a onos:rocks DELETE http://onos-fabric:8181/onos/v1/network/configuration/
    Run    http -a onos:rocks POST http://onos-fabric:8181/onos/v1/network/configuration/ < /opt/cord/test/cord-tester/src/test/setup/${netcfg_file}
    Run    http -a onos:rocks DELETE http://onos-fabric:8181/onos/v1/applications/org.onosproject.segmentrouting/active
    Run    http -a onos:rocks POST http://onos-fabric:8181/onos/v1/applications/org.onosproject.segmentrouting/active
    Sleep    5
    ${netcfg}=    onosUtils.onos_command_execute    onos-fabric    8101    netcfg
    Log    ${netcfg}
    Should Contain    ${netcfg}    vsg-1
    Should Contain    ${netcfg}    vsg-2
    Should Contain    ${netcfg}    vsg-3
    Should Contain    ${netcfg}    "vlan" : 333
    Should Contain    ${netcfg}    "vlan" : 555
    Should Contain    ${netcfg}    "vlan" : 666

Get VSG Subscriber and Tags
    [Documentation]    Retrieves compute node connected on leaf-1 and s/c tags for that particular subscriber
    ${cmd}=    Set Variable    cordvtn-nodes | grep 10.6.1
    ${cnode}=    onosUtils.onos_command_execute    onos-cord    8102    ${cmd}
    @{cnode_on_leaf_1}=    Split String    ${cnode}
    ${novalist}=    Run    . /opt/cord_profile/admin-openrc.sh; nova list --all-tenants | awk '{print $2}' | grep '[a-z]'
    Log    ${novalist}
    @{nova_ids}=    Split To Lines    ${novalist}
    : FOR    ${nova_id}    IN    @{nova_ids}
    \    ${node}=    Run    . /opt/cord_profile/admin-openrc.sh; nova show ${nova_id} | grep :host | awk '{print $4}'
    \    Run Keyword If    '${node}' == '${cnode_on_leaf_1[0]}'    Exit For Loop
    ${mgmt_ip}=    Run    . /opt/cord_profile/admin-openrc.sh; nova show ${nova_id} | grep management | awk '{print $5}'
    ## Get s/c tags for vsg
    Run    ssh-agent bash \r
    Run    ssh-add
    ${result}=    Run    ssh -A ubuntu@${cnode_on_leaf_1[0]} ssh ubuntu@${mgmt_ip} sudo docker ps | grep vsg- | awk '{print $10}'
    @{tags}=    Split String    ${result}    -
    ${s_tag}=    Set Variable    ${tags[1]}
    ${c_tag}=    Set Variable    ${tags[2]}
    Set Suite Variable    ${s_tag}
    Set Suite Variable    ${c_tag}

Execute Dataplane Test
    [Documentation]    Configures interfaces on cord-tester container to connect to vsg instance and validates traffic
    ${i_num}=    Set Variable If
    ...    '${s_tag}' == '333'    1
    ...    '${s_tag}' == '555'    2
    ...    '${s_tag}' == '666'    3
    ${output}=    Run    docker exec cord-tester1 bash -c "sudo echo 'nameserver 192.168.0.1' > /etc/resolv.conf"
    ${output}=    Run    docker exec cord-tester1 bash -c "sudo dhclient vcpe${i_num}.${s_tag}.${c_tag}"
    Sleep    5
    ${output}=    Run    docker exec cord-tester1 bash -c "sudo route add default gw 192.168.0.1 vcpe${i_num}.${s_tag}.${c_tag}"
    ${output}=    Run    docker exec cord-tester1 bash -c "ping -c 3 -I vcpe${i_num}.${s_tag}.${c_tag} 8.8.8.8"
    Log To Console    \n ${output}
    Should Contain   ${output}    64 bytes from 8.8.8.8
    Should Not Contain    ${output}    100% packet loss