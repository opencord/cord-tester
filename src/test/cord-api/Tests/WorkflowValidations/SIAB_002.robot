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

*** Settings ***
Documentation     Test various E2E conditions for seba-in-a-box
Suite Setup       Setup
Suite Teardown    Teardown
#Test Setup        Setup Test
#Test Teardown     Test Cleanup
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           ${VOLTHA_DIR}/tests/atests/common/testCaseUtils.py
Library           ../../Framework/utils/utils.py
Resource          ../../Framework/utils/utils.robot
Library           ../../Framework/restApi.py
Resource          ../../Framework/Subscriber.robot
Resource          ../../Framework/ATTWorkFlowDriver.robot
Resource          ../../Framework/Kubernetes.robot
Resource          ../../Framework/ONU.robot
Resource         ../../Framework/OLT.robot
Resource          ../../Framework/DHCP.robot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${VOLTHA_DIR}              ~/cord/incubator/voltha
${export_kube_config}      export KUBECONFIG=%{HOME}/.kube/config
${kube_node_ip}            localhost
${dst_host_ip}             172.18.0.10
${local_user}              %{USER}
${local_pass}              ${None}

*** Test Cases ***
ONUs in Correct Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configured whitelist with all correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping on all RGs
    [Setup]    None
    [Tags]    test1    stable    latest
    Log    Testing
    ${rg}    Set Variable    rg
    ${length}=    Get Length    ${RGS}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    Set Test Variable    ${${rg}${INDEX}}    ${RGS[${INDEX}]}
    \    Subscriber Ready to Authenticate    ${RGS[${INDEX}]['sn']}
    \    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RGS[${INDEX}]['rg_name']}
    \    Subscriber Service Chain Created    ${RGS[${INDEX}]['sn']}    ${RGS[${INDEX}]['s_tag']}
    \    Validate DHCP and Ping    True    True    eth0    ${RGS[${INDEX}]['s_tag']}    ${RGS[${INDEX}]['c_tag']}    ${RGS[${INDEX}]['dst_ip']}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RGS[${INDEX}]['rg_name']}

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    ${onu_device00}=    Set Variable    PSMO00000000
    ${onu_device01}=    Set Variable    PSMO00000001
    ${onu_device10}=    Set Variable    PSMO00010000
    ${onu_device11}=    Set Variable    PSMO00010001
    ${s_tag_0}=    Convert To Integer     222
    ${s_tag_1}=    Convert To Integer     223
    ${c_tag_00}=    Convert To Integer    111
    ${c_tag_01}=    Convert To Integer    112
    ${c_tag_10}=    Convert To Integer    111
    ${c_tag_11}=    Convert To Integer    112
    ${att_si_id00}=    Retrieve ATT Service Instance ID    ${onu_device00}
    ${att_si_id01}=    Retrieve ATT Service Instance ID    ${onu_device01}
    ${att_si_id10}=    Retrieve ATT Service Instance ID    ${onu_device10}
    ${att_si_id11}=    Retrieve ATT Service Instance ID    ${onu_device11}
    Set Suite Variable    ${att_si_id00}
    Set Suite Variable    ${att_si_id01}
    Set Suite Variable    ${att_si_id10}
    Set Suite Variable    ${att_si_id11}
    ${RG_CONTAINER00}=    Run    kubectl -n voltha get pod|grep "^rg[0]-0"|cut -d' ' -f1
    ${RG_CONTAINER01}=    Run    kubectl -n voltha get pod|grep "^rg[0]-1"|cut -d' ' -f1
    ${RG_CONTAINER10}=    Run    kubectl -n voltha get pod|grep "^rg[1]-0"|cut -d' ' -f1
    ${RG_CONTAINER11}=    Run    kubectl -n voltha get pod|grep "^rg[1]-1"|cut -d' ' -f1
    ${RG_NAMES}=    Create List
    Append To List    ${RG_NAMES}    ${RG_CONTAINER00}
    Append To List    ${RG_NAMES}    ${RG_CONTAINER01}
    Append To List    ${RG_NAMES}    ${RG_CONTAINER10}
    Append To List    ${RG_NAMES}    ${RG_CONTAINER11}
    Set Suite Variable    ${RG_NAMES}
    #Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device00}
    #Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device01}
    #Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device10}
    #Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device11}
    ${dst_ip_00}=    Set Variable    172.18.0.10
    ${dst_ip_01}=    Set Variable    172.18.1.10
    ${dst_ip_10}=    Set Variable    172.19.0.10
    ${dst_ip_11}=    Set Variable    172.19.1.10
    &{rg0}=    Create Dictionary    sn=${onu_device00}    s_tag=${s_tag_0}    c_tag=${c_tag_00}    rg_name=${RG_CONTAINER00}    dst_ip=${dst_ip_00}
    &{rg1}=    Create Dictionary    sn=${onu_device01}    s_tag=${s_tag_0}    c_tag=${c_tag_01}    rg_name=${RG_CONTAINER01}    dst_ip=${dst_ip_01}
    &{rg2}=    Create Dictionary    sn=${onu_device10}    s_tag=${s_tag_1}    c_tag=${c_tag_10}    rg_name=${RG_CONTAINER10}    dst_ip=${dst_ip_10}
    &{rg3}=    Create Dictionary    sn=${onu_device11}    s_tag=${s_tag_1}    c_tag=${c_tag_11}    rg_name=${RG_CONTAINER11}    dst_ip=${dst_ip_11}
    Set Suite Variable    ${rg0}
    Set Suite Variable    ${rg1}
    Set Suite Variable    ${rg2}
    Set Suite Variable    ${rg3}
    @{RGS}=    Create List    ${rg0}    ${rg1}    ${rg2}    ${rg3}
    Set Suite Variable    ${RGS}

Teardown
    Delete All Sessions

Setup Test
    Subscriber Ready to Authenticate

Subscriber Ready to Authenticate
    [Arguments]    ${onu_device}
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}    ONU has been validated - Awaiting Authentication
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}

Subscriber Service Chain Created
    [Arguments]    ${onu_device}    ${s_tag}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}    ONU has been validated - Authentication succeeded
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Service Chain    ${onu_device}    True
    Wait Until Keyword Succeeds    60s    2s    Validate Fabric CrossConnect SI    ${s_tag}    True
    Wait Until Keyword Succeeds    60s    2s    Validate XConnect in ONOS    True

No Subscriber Service Chain
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Service Chain    ${onu_device}    False
    Wait Until Keyword Succeeds    60s    2s    Validate Fabric CrossConnect SI    ${s_tag}    False
    Wait Until Keyword Succeeds    60s    2s    Validate XConnect in ONOS    False

Test Cleanup
    [Documentation]    Restore back to initial state per each test
    Get VOLTHA Status
    Get ONOS Status
    Log Kubernetes Containers Logs Since Time    ${datetime}    ${container_list}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_WHITELIST}
    Wait Until Keyword Succeeds    30s    2s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    30s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_SUBSCRIBER}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Service Chain    ${onu_device}    False
    Wait Until Keyword Succeeds    60s    2s    Validate Fabric CrossConnect SI    ${s_tag}    False
    Restart RG Pod

Restart RG Pod
    Run    kubectl -n voltha delete pod ${RG_CONTAINER}
    ${RG_CONTAINER}=    Wait Until Keyword Succeeds    60s    1s    Run    kubectl -n voltha get pod|grep "^rg[0-]"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}
    Run    kubectl wait -n voltha pod/${RG_CONTAINER} --for condition=Ready --timeout=180s

Reset SIAB Environment
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_SUBSCRIBER}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_WHITELIST}
    Wait Until Keyword Succeeds    30s    2s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    30s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Restart RG Pod
    Wait Until Keyword Succeeds    60s    2s    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Create Whitelist
    Subscriber Ready to Authenticate
    ${RG_CONTAINER}=    Run    kubectl -n voltha get pod|grep "^rg[0-]"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}

Validate XConnect in ONOS
    [Arguments]    ${exists}=True
    ${rc}=    Run And Return RC    http -a karaf:karaf GET http://127.0.0.1:30120/onos/segmentrouting/xconnect|jq -r '.xconnects[].vlanId'|grep 222
    Run Keyword If    '${exists}' == 'True'    Should Be Equal As Integers    ${rc}    0
    ...                                           ELSE    Should Be Equal As Integers    ${rc}    1
