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
Documentation     Test various data plane failure scenarios with ATT workflow
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
${POD_NAME}                 flex-pod1-olt
${KUBERNETES_CONFIGS_DIR}   ~/pod-configs/kubernetes-configs
${HELM_CHARTS_DIR}          ~/helm-charts
${WHITELIST_PATHFILE}       ${CURDIR}/data/${POD_NAME}/ATTWhiteList.json
${SUBSCRIBER_PATHFILE}      ${CURDIR}/data/${POD_NAME}/ATTSubscriber.json
${VOLT_DEVICE_PATHFILE}     ${CURDIR}/data/${POD_NAME}/RealOLTDevice.json
${KUBERNETES_CONF}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.conf
${KUBERNETES_YAML}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.yml
${VOLTHA_POD_NUM}           8

*** Test Cases ***

OLT Reboot
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Reboots OLT
    ...    Validate that pings fail
    ...    Validate successful authentication/DHCP/E2E ping after OLT comes back up
    [Tags]    olt1
    [Teardown]    None
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src0['onu']}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${s_tag}    ${c_tag}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    # Reboot OLT
    Login And Run Command On Remote System    sudo reboot    ${olt_ip}    ${olt_user}    ${olt_pass}   prompt=#
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    False    ${olt_ip}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    True    ${olt_ip}
    Wait Until Keyword Succeeds    120s    10s    Openolt is Up    ${olt_ip}    ${olt_user}    ${olt_pass}
    # Validate authentication and successful pings since the OLT is Up
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${s_tag}    ${c_tag}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

Fabric Switch Reboot
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Reboots Fabric Switch
    ...    Validate that pings fail
    ...    Validate successful authentication/DHCP/E2E ping after OLT comes back up
    #[Setup]    None
    #[Teardown]    None
    [Tags]    fabric1
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src0['onu']}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${s_tag}    ${c_tag}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    # Reboot Fabric Switch
    Login And Run Command On Remote System    sudo reboot    ${fabric_ip}    ${fabric_user}    ${fabric_pass}    prompt=#
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    False    ${fabric_ip}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    True    ${fabric_ip}
    # Validate successful pings since Fabric Switch is Up
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    True    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}

Subscriber(RG) Reboot
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Reboots RG
    ...    Validate that pings fail
    ...    Validate successful authentication/DHCP/E2E ping after OLT comes back up
    [Tags]    RG-reboot
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src0['onu']}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${s_tag}    ${c_tag}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    # Reboot RG
    Login And Run Command On Remote System    sudo reboot    ${src_ip}    ${src_user}    ${src_pass}   prompt=$
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    False    ${fabric_ip}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    150s    10s    Check Remote System Reachability    True    ${src_ip}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}
    # Perform Reauthentication/DHCP and Ping
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${s_tag}    ${c_tag}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

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
    Set Global Variable    ${export_kubeconfig}    export KUBECONFIG=${KUBERNETES_CONF}
    ${olt_ip}=    Evaluate    ${olts}[0].get("ip")
    ${olt_user}=    Evaluate    ${olts}[0].get("user")
    ${olt_pass}=    Evaluate    ${olts}[0].get("pass")
    ${fabric_ip}=    Evaluate    ${fabric_switches}[0].get("ip")
    ${fabric_user}=    Evaluate    ${fabric_switches}[0].get("user")
    ${fabric_pass}=    Evaluate    ${fabric_switches}[0].get("pass")
    ${k8s_node_ip}=    Evaluate    ${nodes}[0].get("ip")
    ${k8s_node_user}=    Evaluate    ${nodes}[0].get("user")
    ${k8s_node_pass}=    Evaluate    ${nodes}[0].get("pass")
    Set Suite Variable    ${olt_ip}
    Set Suite Variable    ${olt_user}
    Set Suite Variable    ${olt_pass}
    Set Suite Variable    ${k8s_node_ip}
    Set Suite Variable    ${k8s_node_user}
    Set Suite Variable    ${k8s_node_pass}
    Set Suite Variable    ${fabric_ip}
    Set Suite Variable    ${fabric_user}
    Set Suite Variable    ${fabric_pass}

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
    Create Whitelist
    Create Subscriber
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
    ${AttWhiteListDict}=    CORDRobot.listToDict    ${AttWhiteListList}    0
    CORD Post    ${ATT_WHITELIST}    ${AttWhiteListDict}

Remove Whitelist
    ${whitelist_id}=    Retrieve Whitelist Entry    ${src0['onu']}
    CORD Delete    ${ATT_WHITELIST}    ${whitelist_id}

Update Whitelist with Wrong Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${src0['onu']}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 55 }    ${whitelist_id}

Update Whitelist with Correct Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${src0['onu']}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": ${onu_location} }    ${whitelist_id}

Create Subscriber
    ${SubscriberDict}=    CORDRobot.listToDict    ${SubscriberList}    0
    Wait Until Keyword Succeeds    120s    15s    CORD Post    ${VOLT_SUBSCRIBER}    ${SubscriberDict}

Remove Subscriber
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Delete    ${VOLT_SUBSCRIBER}    ${subscriber_id}

Create VOLT
    CORD Post    ${VOLT_DEVICE}    ${VoltDeviceDict}

Update ONU AdminState
    [Arguments]    ${new_admin_state}
    ${onudevice_id}=    Retrieve ONU Device    ${src0['onu']}
    CORD Put    ${VOLT_DEVICE}    {"admin_state": ${new_admin_state} }    ${onudevice_id}
