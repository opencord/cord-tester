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
Documentation     Test various with ATT workflow using multiple ONUs
Suite Setup       Setup Suite
Suite Teardown    Teardown Suite
Test Setup        Setup Test
Test Teardown     Teardown Test
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           CORDRobot
Library           ImportResource  resources=CORDRobot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${POD_NAME}                 onlab-pod1-qa
${KUBERNETES_CONFIGS_DIR}   ~/pod-configs/kubernetes-configs
${HELM_CHARTS_DIR}          ~/helm-charts
${WHITELIST_PATHFILE}       ${CURDIR}/data/${POD_NAME}/ATTWhiteList.json
${SUBSCRIBER_PATHFILE}      ${CURDIR}/data/${POD_NAME}/ATTSubscriber.json
${VOLT_DEVICE_PATHFILE}     ${CURDIR}/data/${POD_NAME}/RealOLTDevice.json
${KUBERNETES_CONF}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.conf
${KUBERNETES_YAML}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.yml
${VOLTHA_POD_NUM}           8

*** Test Cases ***
ONU in Correct Location with two ONUs
    [Documentation]    Test with two ONUs(same s-tag) - authenticate/dhcp/ping on both the ONUs
    ...    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct first ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Configure whitelist with correct details for the second ONU location
    ...    Validate successful authentication/DHCP/E2E ping for the second ONU
    ...    Validates that the first ONU can still ping
    #[Setup]    None
    [Teardown]    None
    [Tags]    multipleONU-test1
    Log    $[src0['onu']}
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src0['onu']}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${src0['s_tag']}    ${src0['c_tag']}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    #Second ONU
    Log    $[src1['onu']}
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src1['onu']}
    Validate Authentication    True    ${src1['dp_iface_name']}    wpa_supplicant.conf    ${src1['ip']}    ${src1['user']}    ${src1['pass']}    ${src1['container_type']}    ${src1['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src1['onu']}
    Validate DHCP and Ping    True    True    ${src1['dp_iface_name']}    ${src1['s_tag']}    ${src1['c_tag']}    ${dst1['dp_iface_ip_qinq']}    ${src1['ip']}    ${src1['user']}    ${src1['pass']}    ${src1['container_type']}    ${src1['container_name']}    ${dst1['dp_iface_name']}    ${dst1['ip']}    ${dst1['user']}    ${dst1['pass']}    ${dst1['container_type']}    ${dst1['container_name']}
    # Validate that the first ONU can still ping
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${src0['s_tag']}    ${src0['c_tag']}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

Deletion of one ONU from the whitelist while other ONU exists
    [Documentation]    Test with two ONUs(same s-tag) - delete one ONU from the whitelist
    ...    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    After validating authentication/dhcp/ping from the above tests
    ...    Delete the second ONU from the whitelist
    ...    Validate that pings fail on the second ONU
    ...    Validate that the first ONU can still ping
    [Setup]    None
    [Teardown]    None
    [Tags]    multipleONU-test2
    #Second ONU
    Remove Whitelist    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst1['dp_iface_ip_qinq']}    ${src1['dp_iface_name']}    ${src1['ip']}    ${src1['user']}    ${src1['pass']}   ${src1['container_type']}    ${src1['container_name']}
    # Validate that the first ONU can still ping
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${src0['s_tag']}    ${src0['c_tag']}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

Readd the deleted ONU to the whitelist while other ONU exists
    [Documentation]    Test with two ONUs(same s-tag) - readd deleted ONU to the whitelist
    ...    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    After validating authentication/dhcp/ping from the above tests
    ...    Add the second ONU to the whitelist
    ...    Perform authentication/dhcp/ping on the second ONU
    ...    Validate that pings succeed on the second ONU
    ...    Validate that the first ONU can still ping
    [Setup]    None
    [Teardown]    None
    [Tags]    multipleONU-test3
    #Second ONU
    Create Whitelist    1
    Log    $[src1['onu']}
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src1['onu']}
    Validate Authentication    True    ${src1['dp_iface_name']}    wpa_supplicant.conf    ${src1['ip']}    ${src1['user']}    ${src1['pass']}    ${src1['container_type']}    ${src1['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src1['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src1['onu']}
    Validate DHCP and Ping    True    True    ${src1['dp_iface_name']}    ${src1['s_tag']}    ${src1['c_tag']}    ${dst1['dp_iface_ip_qinq']}    ${src1['ip']}    ${src1['user']}    ${src1['pass']}    ${src1['container_type']}    ${src1['container_name']}    ${dst1['dp_iface_name']}    ${dst1['ip']}    ${dst1['user']}    ${dst1['pass']}    ${dst1['container_type']}    ${dst1['container_name']}
    # Validate that the first ONU can still ping
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${src0['s_tag']}    ${src0['c_tag']}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

*** Keywords ***
Setup Suite
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    ${att_workflow_service_id}=    Get Service Owner Id    ${ATT_SERVICE}
    ${volt_service_id}=    Get Service Owner Id    ${VOLT_SERVICE}
    ${AttWhiteListList}=    CORDRobot.jsonToList    ${WHITELIST_PATHFILE}   AttWhiteListInfo
    Set Suite Variable    ${AttWhiteListList}
    ${AttWhiteListDict}=    CORDRobot.listToDict    ${AttWhiteListList}    0
    ${AttWhiteListDict}=    CORDRobot.setFieldValueInDict    ${AttWhiteListDict}    owner_id    ${att_workflow_service_id}
    Set Suite Variable    ${att_workflow_service_id}
    ${onu_location}=   Get From Dictionary    ${AttWhiteListDict}    pon_port_id
    Set Global Variable    ${onu_location}
    ${SubscriberList}=    CORDRobot.jsonToList    ${SUBSCRIBER_PATHFILE}   SubscriberInfo
    Set Global Variable    ${SubscriberList}
    ${SubscriberDict}=    CORDRobot.listToDict    ${SubscriberList}    0
    ${s_tag}=    CORDRobot.getFieldValueFromDict    ${SubscriberDict}   s_tag
    ${c_tag}=    CORDRobot.getFieldValueFromDict    ${SubscriberDict}   c_tag
    ${VoltDeviceList}=    CORDRobot.jsonToList    ${VOLT_DEVICE_PATHFILE}   VOLTDeviceInfo
    ${VoltDeviceDict}=    CORDRobot.setFieldValueInDict    ${VoltDeviceList[0]}    volt_service_id    ${volt_service_id}
    Set Global Variable    ${VoltDeviceList}
    Set Global Variable    ${VoltDeviceDict}
    Set Suite Variable    ${s_tag}
    Set Suite Variable    ${c_tag}
    ${olt_ip}=    Evaluate    ${olts}[0].get("ip")
    ${olt_user}=    Evaluate    ${olts}[0].get("user")
    ${olt_pass}=    Evaluate    ${olts}[0].get("pass")
    ${k8s_node_ip}=    Evaluate    ${nodes}[0].get("ip")
    ${k8s_node_user}=    Evaluate    ${nodes}[0].get("user")
    ${k8s_node_pass}=    Evaluate    ${nodes}[0].get("pass")
    Set Suite Variable    ${olt_ip}
    Set Suite Variable    ${olt_user}
    Set Suite Variable    ${olt_pass}
    Set Suite Variable    ${k8s_node_ip}
    Set Suite Variable    ${k8s_node_user}
    Set Suite Variable    ${k8s_node_pass}
    Set Global Variable    ${export_kubeconfig}    export KUBECONFIG=${KUBERNETES_CONF}
    @{container_list}=    Create List
    Append To List    ${container_list}    att-workflow-att-workflow-driver
    Append To List    ${container_list}    seba-services-volt
    Append To List    ${container_list}    seba-services-rcord
    Append To List    ${container_list}    onos
    Append To List    ${container_list}    seba-services-fabric-crossconnect
    Append To List    ${container_list}    xos-core
    Append To List    ${container_list}    vcore
    Set Suite Variable    ${container_list}
    Set Deployment Config Variables
    ${datetime}=    Get Current Datetime On Kubernetes Node    ${k8s_node_ip}    ${k8s_node_user}    ${k8s_node_pass}
    Set Suite Variable    ${datetime}

Teardown Suite
    [Documentation]    Performs any additional cleanup required
    Log    Suite Teardown cleanup
    Delete All Sessions

Setup Test
    [Documentation]    Re-create Subscriber, whitelist, and olt-device models to test
    Log    Re-creating objects
    ${datetime}=    Get Current Datetime On Kubernetes Node    ${k8s_node_ip}    ${k8s_node_user}    ${k8s_node_pass}
    Set Suite Variable    ${datetime}
    Create Whitelist   0
    Create Whitelist   1
    Create Subscriber   0
    Create Subscriber   1
    Create VOLT
    Wait Until Keyword Succeeds    200s    15s    Validate OLT States    ACTIVE    ENABLED    ${olt_ip}

Teardown Test
    [Documentation]    Delete xos objects, kills processes and cleans up interfaces on src+dst servers
    Get VOLTHA Status
    Get ONOS Status
    Clean Up Linux
    Clean Up XOS
    Log Kubernetes Containers Logs Since Time    ${datetime}    ${container_list}

Clean Up Linux
    [Documentation]    Kill processes and clean up interfaces on src+dst servers
    Run Keyword And Ignore Error    Kill Linux Process    [w]pa_supplicant    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword And Ignore Error    Kill Linux Process    [d]hclient    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword If    '${dst0['ip']}' != '${None}'    Run Keyword And Ignore Error    Kill Linux Process    [d]hcpd    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    Delete IP Addresses from Interface on Remote Host    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword If    '${dst0['ip']}' != '${None}'    Delete Interface on Remote Host    ${dst0['dp_iface_name']}.${s_tag}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

Clean Up XOS
    [Documentation]    Clean up all XOS objects and reinstall voltha after OLT reboots
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_SUBSCRIBER}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_WHITELIST}
    Sleep    20s
    Wait Until Keyword Succeeds    30s    2s    Validate Subscriber Count    0
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_DEVICE}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_SERVICEINSTANCES}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    False    ${olt_ip}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    True    ${olt_ip}
    Wait Until Keyword Succeeds    120s    10s    Openolt is Up    ${olt_ip}    ${olt_user}    ${olt_pass}

Create Whitelist
    [Arguments]    ${index_id}
    ${AttWhiteListDict}=    CORDRobot.listToDict    ${AttWhiteListList}    ${index_id}
    ${AttWhiteListDict}=    CORDRobot.setFieldValueInDict    ${AttWhiteListDict}    owner_id    ${att_workflow_service_id}
    CORD Post    ${ATT_WHITELIST}    ${AttWhiteListDict}

Remove Whitelist
    [Arguments]    ${onu_device}
    Log    ${onu_device}
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Delete    ${ATT_WHITELIST}    ${whitelist_id}

Update Whitelist with Wrong Location
    [Arguments]    ${onu_device}
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 5345 }    ${whitelist_id}

Update Whitelist with Correct Location
    [Arguments]    ${onu_device}
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": ${onu_location} }    ${whitelist_id}

Create Subscriber
    [Arguments]    ${index_id}
    ${SubscriberDict}=    CORDRobot.listToDict    ${SubscriberList}    ${index_id}
    Wait Until Keyword Succeeds    120s    15s    CORD Post    ${VOLT_SUBSCRIBER}    ${SubscriberDict}

Remove Subscriber
    [Arguments]   ${c_tag}
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Delete    ${VOLT_SUBSCRIBER}    ${subscriber_id}

Create VOLT
    CORD Post    ${VOLT_DEVICE}    ${VoltDeviceDict}

Update ONU AdminState
    [Arguments]    ${onu_device}    ${new_admin_state}
    ${onudevice_id}=    Retrieve ONU Device    ${onu_device}
    CORD Put    ${VOLT_DEVICE}    ${"admin_state": ${new_admin_state} }    ${onudevice_id}

