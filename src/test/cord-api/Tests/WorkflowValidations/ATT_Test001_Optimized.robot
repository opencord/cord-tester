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
Documentation     Test various end-to-end scenarios with ATT workflow
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
ONU in Correct Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    [Setup]    None
    [Teardown]    None
    [Tags]    test1
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Correct Location -> Remove ONU from Whitelist -> Add ONU to Whitelist
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Remove ONU from whitelist
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Add ONU to whitelist
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    test2
    [Setup]    None
    [Teardown]    None
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    # Disable ONU   
    Clean Up Linux
    Remove Whitelist
    Wait Until Keyword Succeeds    60s    2s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Whitelist
    Wait Until Keyword Succeeds    120s    5s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Correct Location -> ONU in Wrong Location -> ONU in Correct Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Update whitelist with wrong ONU location
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Update whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    test3
    [Setup]    None
    [Teardown]    None
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Clean Up Linux
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    60s    2s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Update Whitelist with Correct Location
    Wait Until Keyword Succeeds    120s    5s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Correct Location -> Remove Subscriber -> Create Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Remove subscriber model
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Recreate subscriber model
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    test4
    [Setup]    None
    [Teardown]    None
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Clean Up Linux
    Remove Subscriber
    Sleep    10s
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}


ONU in Correct Location (Skip Subscriber Provisioning) -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location and skip provisioning subscriber
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Setup]    None
    [Tags]    test5
    Create Whitelist
    Create VOLT
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Wrong Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with wrong ONU location
    ...    Validate failed authentication/DHCP/E2E ping
    [Tags]    test9
    [Setup]    None
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Clean Up Linux
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Correct Location (Skip Authentication)
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location and skip RG authentication
    ...    Validate failed authentication/DHCP/E2E ping
    [Tags]    test6
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU not in Whitelist
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Skip whitelist configuration for ONU
    ...    Validate failed authentication/DHCP/E2E ping
    [Setup]    None
    [Tags]    test7
    Create Subscriber
    Create VOLT
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU not in Whitelist (Skip Subscriber Provisioning) -> Add ONU to Whitelist -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Skip whitelist configuration for ONU and subscriber provisioning
    ...    Validate successful authentication but failed DHCP/E2E ping
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Setup]    None
    [Tags]    test8
    Create VOLT
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Whitelist
    Wait Until Keyword Succeeds    60s    2s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

ONU in Wrong Location (Skip Subscriber Provisioning) -> ONU in Correct Location -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with wrong ONU location and skip subscriber provisioning
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Setup]    None
    [Tags]    test10
    Create VOLT
    Create Whitelist
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Validate Authentication    False    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Update Whitelist with Correct Location
    Wait Until Keyword Succeeds    60s    2s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Clean Up Linux
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    ${src_iface}    wpa_supplicant.conf    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Validate DHCP and Ping    True    True    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}    ${dst_dp_iface}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

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
    ${onu_device}=   Get From Dictionary    ${AttWhiteListDict}    serial_number
    Set Global Variable    ${onu_device}
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
    # Read variables from yaml file
    ${src_ip}=    Evaluate    ${hosts}.get("src").get("ip")
    ${src_user}=    Evaluate    ${hosts}.get("src").get("user")
    ${src_pass}=    Evaluate    ${hosts}.get("src").get("pass")
    ${src_container_type}=    Evaluate    ${hosts}.get("src").get("container_type")
    ${src_container_name}=    Evaluate    ${hosts}.get("src").get("container_name")
    ${src_iface}=    Evaluate    ${hosts}.get("src").get("dp_iface_name")
    ${dst_ip}=    Evaluate    ${hosts}.get("dst").get("ip")
    ${dst_user} =    Evaluate    ${hosts}.get("dst").get("user")
    ${dst_pass}=    Evaluate    ${hosts}.get("dst").get("pass")
    ${dst_container_type}=    Evaluate    ${hosts}.get("dst").get("container_type")
    ${dst_container_name}=    Evaluate    ${hosts}.get("dst").get("container_name")
    ${dst_dp_iface}=    Evaluate    ${hosts}.get("dst").get("dp_iface_name")
    ${dst_dp_ip}=    Evaluate    ${hosts}.get("dst").get("dp_iface_ip_qinq")
    ${olt_ip}=    Evaluate    ${olts}[0].get("ip")
    ${olt_user}=    Evaluate    ${olts}[0].get("user")
    ${olt_pass}=    Evaluate    ${olts}[0].get("pass")
    ${k8s_node_ip}=    Evaluate    ${nodes}[0].get("ip")
    ${k8s_node_user}=    Evaluate    ${nodes}[0].get("user")
    ${k8s_node_pass}=    Evaluate    ${nodes}[0].get("pass")
    Set Suite Variable    ${src_ip}
    Set Suite Variable    ${src_user}
    Set Suite Variable    ${src_pass}
    Set Suite Variable    ${src_container_type}
    Set Suite Variable    ${src_container_name}
    Set Suite Variable    ${src_iface}
    Set Suite Variable    ${dst_ip}
    Set Suite Variable    ${dst_user}
    Set Suite Variable    ${dst_pass}
    Set Suite Variable    ${dst_container_type}
    Set Suite Variable    ${dst_container_name}
    Set Suite Variable    ${dst_dp_iface}
    Set Suite Variable    ${dst_dp_ip}
    Set Suite Variable    ${olt_ip}
    Set Suite Variable    ${olt_user}
    Set Suite Variable    ${olt_pass}
    Set Suite Variable    ${k8s_node_ip}
    Set Suite Variable    ${k8s_node_user}
    Set Suite Variable    ${k8s_node_pass}
    @{container_list}=    Create List
    Append To List    ${container_list}    att-workflow-att-workflow-driver
    Append To List    ${container_list}    seba-services-volt
    Append To List    ${container_list}    seba-services-rcord
    Append To List    ${container_list}    onos
    Append To List    ${container_list}    seba-services-fabric-crossconnect
    Append To List    ${container_list}    xos-core
    Append To List    ${container_list}    vcore
    Set Suite Variable    ${container_list}
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
    Run Keyword And Ignore Error    Kill Linux Process    [w]pa_supplicant    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword And Ignore Error    Kill Linux Process    [d]hclient    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${dst_ip}' != '${None}'    Run Keyword And Ignore Error    Kill Linux Process    [d]hcpd    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Delete IP Addresses from Interface on Remote Host    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${dst_ip}' != '${None}'    Delete Interface on Remote Host    ${dst_dp_iface}.${s_tag}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}

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
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Delete    ${ATT_WHITELIST}    ${whitelist_id}

Update Whitelist with Wrong Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 55 }    ${whitelist_id}

Update Whitelist with Correct Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": ${onu_location} }    ${whitelist_id}

Create Subscriber
    ${SubscriberDict}=    CORDRobot.listToDict    ${SubscriberList}    0
    Wait Until Keyword Succeeds    120s    15s    CORD Post    ${VOLT_SUBSCRIBER}    ${SubscriberDict}

Remove Subscriber
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Delete    ${VOLT_SUBSCRIBER}    ${subscriber_id}

Create VOLT
    CORD Post    ${VOLT_DEVICE}    ${VoltDeviceDict}
