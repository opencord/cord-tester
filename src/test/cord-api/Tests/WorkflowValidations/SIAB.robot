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
Test Setup        Setup Test
Test Teardown     Test Cleanup
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           CORDRobot
Library           ImportResource  resources=CORDRobot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${VOLTHA_DIR}              ~/cord/incubator/voltha
${WHITELIST_FILENAME}      SIABWhitelist
${SUBSCRIBER_FILENAME}     SIABSubscriber
${OLT_DEVICE_FILENAME}     SIABOLTDevice
${WHITELIST_PATHFILE}      ${CURDIR}/data/${WHITELIST_FILENAME}.json
${SUBSCRIBER_PATHFILE}     ${CURDIR}/data/${SUBSCRIBER_FILENAME}.json
${VOLT_DEVICE_PATHFILE}    ${CURDIR}/data/${OLT_DEVICE_FILENAME}.json
${export_kube_config}      export KUBECONFIG=%{HOME}/.kube/config
${kube_node_ip}            127.0.0.1
${dst_host_ip}             172.18.0.10
${local_user}              %{USER}
${local_pass}              ${None}

*** Test Cases ***
ONU in Correct Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    [Setup]    None
    [Tags]    stable    latest    test1    multicast
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Put    ${VOLT_SUBSCRIBER}    {"status":"disabled"}    ${subscriber_id}
    No Subscriber Service Chain
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    CORD Put    ${VOLT_SUBSCRIBER}    {"status":"awaiting-auth"}    ${subscriber_id}
    # ATTWD SI auth_state is already "APPROVED" here from previous auth... not sure if this matters
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Correct Location -> Remove ONU from Whitelist -> Add ONU to Whitelist
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Remove ONU from whitelist
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Add ONU to whitelist
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    stable    latest    test2
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Reset SIAB Environment
    Remove Whitelist
    Wait Until Keyword Succeeds    120s    2s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU not found in whitelist
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    No Subscriber Service Chain
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Reset SIAB Environment
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Correct Location -> ONU in Wrong Location -> ONU in Correct Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Update whitelist with wrong ONU location
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Update whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    stable    latest    test3
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU activated in wrong location
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    No Subscriber Service Chain
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Update Whitelist with Correct Location
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Correct Location -> Remove Subscriber -> Create Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Remove subscriber model
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Recreate subscriber model
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    stable    latest    test4
    Subscriber Ready to Authenticate
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Remove Subscriber
    No Subscriber Service Chain
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Correct Location (Skip Subscriber Provisioning) -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location and skip provisioning subscriber
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    stable    latest    test5
    Remove Subscriber
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Correct Location (Skip Authentication)
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with correct ONU location and skip RG authentication
    ...    Validate failed authentication/DHCP/E2E ping
    [Tags]    stable    latest    test6
    Subscriber Ready to Authenticate
    No Subscriber Service Chain
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU not in Whitelist
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Skip whitelist configuration for ONU
    ...    Validate failed authentication/DHCP/E2E ping
    [Tags]    stable    latest    test7
    [Setup]    Simple Setup
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Create Subscriber
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}    pre-provisioned
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU not found in whitelist
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}    pre-provisioned
    No Subscriber Service Chain
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU not in Whitelist (Skip Subscriber Provisioning) -> Add ONU to Whitelist -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Skip whitelist configuration for ONU and subscriber provisioning
    ...    Validate successful authentication but failed DHCP/E2E ping
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    latest    test8    stable
    [Setup]    Simple Setup
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU not found in whitelist
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Create Whitelist
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    pre-provisioned    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Wrong Location
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with wrong ONU location
    ...    Validate failed authentication/DHCP/E2E ping
    [Tags]    latest    test9    stable
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU activated in wrong location
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU activated in wrong location
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}
    No Subscriber Service Chain
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

ONU in Wrong Location (Skip Subscriber Provisioning) -> ONU in Correct Location -> Provision Subscriber
    [Documentation]    Validates E2E Ping Connectivity and object states for the given scenario:
    ...    Configure whitelist with wrong ONU location and skip subscriber provisioning
    ...    Validate failed authentication/DHCP/E2E ping
    ...    Configure whitelist with correct ONU location
    ...    Validate successful authentication (expected with the ONF pod setup) but failed DHCP/E2E ping
    ...    Provision subscriber
    ...    Validate successful authentication/DHCP/E2E ping
    [Tags]    stable    latest    test10
    [Setup]    Simple Setup
    Wait Until Keyword Succeeds    60s    2s    Create Whitelist
    Update Whitelist with Wrong Location
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    UNKNOWN    DISABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}    ONU activated in wrong location
    Validate Authentication    False    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING    ${onu_device}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Update Whitelist with Correct Location
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    Validate DHCP and Ping    False    False    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Restart RG Pod
    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}    pre-provisioned
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

Multicast Join Fails -> Authenticate, run DHCP -> Multicast Join Succeeds
    [Documentation]    Validates Multicast Connectivity and object states for the given scenario:
    ...    (Assumes multicast server upstream of BNG)
    ...    (Assumes pimd server running on BNG)
    ...    Configure whitelist with correct ONU location
    ...    Run multicast client on RG
    ...    Validate that no multicast traffic flowing yet
    ...    Validate successful authentication/DHCP/E2E ping
    ...    Run multicast client on RG
    ...    Validate that multicast traffic is flowing E2E
    [Tags]    latest    test11    multicast
    Subscriber Ready to Authenticate
    Validate Multicast    False    eth0    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Validate Authentication    True    eth0    wpa_supplicant.conf    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Subscriber Service Chain Created
    Validate DHCP and Ping    True    True    eth0    ${s_tag}    ${c_tag}    ${dst_host_ip}    ${kube_node_ip}    ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}
    Validate Multicast    True    eth0    ${kube_node_ip}     ${local_user}    ${local_pass}    K8S    ${RG_CONTAINER}

*** Keywords ***
Setup
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
    Log    ${onu_device}
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
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    Set Suite Variable    ${whitelist_id}
    ${att_si_id}=    Retrieve ATT Service Instance ID    ${onu_device}
    Set Suite Variable    ${att_si_id}
    ${RG_CONTAINER}=    Run    kubectl -n voltha get pod|grep "^rg[0-]"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}
    ## Validate ATT Workflow SI
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    @{container_list}=    Create List
    Append To List    ${container_list}    att-workflow-att-workflow-driver
    Append To List    ${container_list}    seba-services-fabric-crossconnect
    Append To List    ${container_list}    seba-services-rcord
    Append To List    ${container_list}    seba-services-volt
    Append To List    ${container_list}    xos-core
    Append To List    ${container_list}    vcore
    Set Suite Variable    ${container_list}
    Setup SSH Keys to Localhost
    ${datetime}=    Get Current Datetime On Kubernetes Node    ${kube_node_ip}    ${local_user}    ${local_pass}
    Set Suite Variable    ${datetime}

Teardown
    Setup Test
    Delete All Sessions

Setup Test
    ${datetime}=    Run    date +"%Y-%m-%dT%H:%M:%S.%NZ"
    Set Suite Variable    ${datetime}
    Wait Until Keyword Succeeds    60s    2s    Create Subscriber
    Wait Until Keyword Succeeds    60s    2s    Create Whitelist
    Subscriber Ready to Authenticate

Subscriber Ready to Authenticate
    Wait Until Keyword Succeeds    60s    15s    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}    ONU has been validated - Awaiting Authentication
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${onu_device}

Subscriber Service Chain Created
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}    ONU has been validated - Authentication succeeded
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Service Chain    ${onu_device}    True
    Wait Until Keyword Succeeds    60s    2s    Validate Fabric CrossConnect SI    ${s_tag}    True
    Wait Until Keyword Succeeds    60s    2s    Validate XConnect in ONOS    True

No Subscriber Service Chain
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Service Chain    ${onu_device}    False
    Wait Until Keyword Succeeds    60s    2s    Validate Fabric CrossConnect SI    ${s_tag}    False
    Wait Until Keyword Succeeds    60s    2s    Validate XConnect in ONOS    False

Simple Setup
    ${datetime}=    Run    date +"%Y-%m-%dT%H:%M:%S.%NZ"
    Set Suite Variable    ${datetime}
    ${RG_CONTAINER}=    Run    kubectl -n voltha get pod|grep "^rg[0-]"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}

Test Cleanup
    [Documentation]    Restore back to initial state per each test
    Get VOLTHA Status
    Get ONOS Status    ${kube_node_ip}
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

Create Whitelist
    ${AttWhiteListDict}=    CORDRobot.listToDict    ${AttWhiteListList}    0
    ${resp}=    CORD Post    ${ATT_WHITELIST}    ${AttWhiteListDict}
    ${id}=    Get From Dictionary    ${resp.json()}    id
    Set Global Variable    ${whitelist_id}

Remove Whitelist
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Delete    ${ATT_WHITELIST}    ${whitelist_id}

Create Subscriber
    ${SubscriberDict}=    CORDRobot.listToDict    ${SubscriberList}    0
    CORD Post    ${VOLT_SUBSCRIBER}    ${SubscriberDict}

Remove Subscriber
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Delete    ${VOLT_SUBSCRIBER}    ${subscriber_id}

Create VOLT
    CORD Post    ${VOLT_DEVICE}    ${VoltDeviceDict}

Update Whitelist with Wrong Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 55 }    ${whitelist_id}

Update Whitelist with Correct Location
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_device}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": ${onu_location} }    ${whitelist_id}

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

Setup SSH Keys to Localhost
    Run    yes y 2>/dev/null | ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
    Run    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
    Run    chmod og-wx ~/.ssh/authorized_keys
