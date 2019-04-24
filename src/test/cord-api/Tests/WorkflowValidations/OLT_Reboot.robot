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
Library           ../../Framework/utils/utils.py
Resource          ../../Framework/utils/utils.robot
Library           ../../Framework/restApi.py
Resource          ../../Framework/Subscriber.robot
Resource          ../../Framework/ATTWorkFlowDriver.robot
Resource          ../../Framework/Kubernetes.robot
Resource          ../../Framework/ONU.robot
Resource          ../../Framework/OLT.robot
Resource          ../../Framework/DHCP.robot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${NUM_REBOOTS}      5
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
Reboot OLT
    [Documentation]    Validate olt creation -> olt deletion
    ${reboot_count}=    Convert To Integer    ${NUM_REBOOTS}
    : FOR    ${INDEX}    IN RANGE    0    ${reboot_count}
    \    Log To Console    \n Reboot Attempt - ${INDEX}
    \    Setup Test
    \    Wait Until Keyword Succeeds    300s    5s    Device in VOLTHA and ONOS
    \    Wait Until Keyword Succeeds    Validate OLT States in XOS
    \    Teardown Test

*** Keywords ***
Device in VOLTHA and ONOS
    ${voltha_num}=    Run    curl -s -U voltha:admin http://10.90.0.101:30125/api/v1/devices| grep '10.90.0.114' | grep '"admin_state":"ENABLED"' | grep '"connect_status":"REACHABLE"' | grep '"oper_status":"ACTIVE"' | wc -l
    ${onos_num}=    Run    sshpass -p'rocks' ssh onos@10.90.0.101 -p 30115 devices | grep voltha | grep OLT | grep available=true | grep local-status=connected | wc -l
    Should Contain    ${voltha_num}    1
    Should Contain    ${onos_num}    1

Validate OLT States in XOS
    ${xos_output}=    Run    curl -s -u admin@opencord.org:letmein http://10.90.0.101:30001/xosapi/v1/volt/oltdevices
    Log    ${xos_output}
    ${xos_num}=    Run    curl -s -u admin@opencord.org:letmein http://10.90.0.101:30001/xosapi/v1/volt/oltdevices | grep '10.90.0.114' | grep '"admin_state": "ENABLED"' | grep '"oper_status": "ACTIVE"' | wc -l
    Should Contain    ${xos_num}

Setup Suite
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    ${att_workflow_service_id}=    Get Service Owner Id    ${ATT_SERVICE}
    ${volt_service_id}=    Get Service Owner Id    ${VOLT_SERVICE}
    ${AttWhiteListList}=    utils.jsonToList    ${WHITELIST_PATHFILE}   AttWhiteListInfo
    Set Suite Variable    ${AttWhiteListList}
    ${AttWhiteListDict}=    utils.listToDict    ${AttWhiteListList}    0
    ${AttWhiteListDict}=    utils.setFieldValueInDict    ${AttWhiteListDict}    owner_id    ${att_workflow_service_id}
    ${onu_device}=   Get From Dictionary    ${AttWhiteListDict}    serial_number
    Set Global Variable    ${onu_device}
    ${onu_location}=   Get From Dictionary    ${AttWhiteListDict}    pon_port_id
    Set Global Variable    ${onu_location}
    ${SubscriberList}=    utils.jsonToList    ${SUBSCRIBER_PATHFILE}   SubscriberInfo
    Set Global Variable    ${SubscriberList}
    ${SubscriberDict}=    utils.listToDict    ${SubscriberList}    0
    ${s_tag}=    utils.getFieldValueFromDict    ${SubscriberDict}   s_tag
    ${c_tag}=    utils.getFieldValueFromDict    ${SubscriberDict}   c_tag
    ${VoltDeviceList}=    utils.jsonToList    ${VOLT_DEVICE_PATHFILE}   VOLTDeviceInfo
    ${VoltDeviceDict}=    utils.setFieldValueInDict    ${VoltDeviceList[0]}    volt_service_id    ${volt_service_id}
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
    Create Whitelist
    Create Subscriber
    Create VOLT

Teardown Test
    [Documentation]    Delete xos objects, kills processes and cleans up interfaces on src+dst servers
    Clean Up XOS
    Log Kubernetes Containers Logs Since Time    ${datetime}    ${container_list}

Clean Up XOS
    [Documentation]    Clean up all XOS objects and reinstall voltha after OLT reboots
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_SUBSCRIBER}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_WHITELIST}
    Sleep    20s
    Wait Until Keyword Succeeds    30s    2s    Validate Subscriber Count    0
    Sleep    10s
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_DEVICE}
    Sleep    20s
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_SERVICEINSTANCES}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    False    ${olt_ip}
    Wait Until Keyword Succeeds    120s    10s    Check Remote System Reachability    True    ${olt_ip}
    Wait Until Keyword Succeeds    300s    1s    Openolt is Up    ${olt_ip}    ${olt_user}    ${olt_pass}

Create Whitelist
    ${AttWhiteListDict}=    utils.listToDict    ${AttWhiteListList}    0
    CORD Post    ${ATT_WHITELIST}    ${AttWhiteListDict}

Create Subscriber
    ${SubscriberDict}=    utils.listToDict    ${SubscriberList}    0
    Wait Until Keyword Succeeds    120s    15s    CORD Post    ${VOLT_SUBSCRIBER}    ${SubscriberDict}

Create VOLT
    CORD Post    ${VOLT_DEVICE}    ${VoltDeviceDict}
