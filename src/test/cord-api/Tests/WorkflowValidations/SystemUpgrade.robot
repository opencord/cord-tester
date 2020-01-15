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
Documentation     In-Service-Software-Upgrade test suite
Suite Setup       Setup Suite
Suite Teardown    Teardown Suite
Test Template     Perform Operation and Validate
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
${KUBERNETES_CONF}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.conf
${KUBERNETES_YAML}          ${KUBERNETES_CONFIGS_DIR}/${POD_NAME}.yml
${onos_tag}                 1.13.9
${voltha_tag}               voltha-1.7

*** Test Cases ***
Restart ATT Workflow    RESTART    att-workflow-driver

Restart OLT Service    RESTART    seba-services-volt

Restart RCORD Service    RESTART    rcord

Restart Fabric-Crossconnect Service    RESTART    fabric-crossconnect

Restart ONOS Service    RESTART    onos-service

Upgrade RCORD Service    UPGRADE    rcord

Upgrade Fabric-Crossconnect   UPGRADE    fabric-crossconnect

Upgrade ONOS Service    UPGRADE    onos-service

Upgrade ONOS Controller    UPGRADE    ONOS    ONOS

Upgrade VOLTHA    UPGRADE    VOLTHA    VOLTHA
    [Tags]    notready

*** Keywords ***
Setup Suite
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    Set Global Variable    ${export_kubeconfig}    export KUBECONFIG=${KUBERNETES_CONF}
    Set Deployment Config Variables
    Clean Up Linux
    Configure Subscriber

Configure Subscriber
    Wait Until Keyword Succeeds    300s    15s    Validate ONU States    ACTIVE    ENABLED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth    ${src0['onu']}
    Validate Authentication    True    ${src0['dp_iface_name']}    wpa_supplicant.conf    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${src0['onu']}
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled    ${src0['onu']}
    Validate DHCP and Ping    True    True    ${src0['dp_iface_name']}    ${src0['s_tag']}    ${src0['c_tag']}    ${dst0['dp_iface_ip_qinq']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}    ${dst0['dp_iface_name']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

Teardown Suite
    [Documentation]    Performs any additional cleanup required
    Log    Suite Teardown cleanup
    Delete All Sessions

Perform Operation and Validate
    [Documentation]    Start/stop/upgrade service and validate dataplane
    [Arguments]    ${operation}    ${pod_prefix}    ${controller}=${NONE}
    ${pod_name}    ${namespace}=    Get Pod Name    ${pod_prefix}
    Wait Until Keyword Succeeds    90s    2s    Subscriber Provisioned    ${server_ip}    ${src0['onu']}    ${src0['s_tag']}
    Wait Until Keyword Succeeds    60s    2s    Subscriber Service Chain Created    ${src0['onu']}    ${src0['s_tag']}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    True    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}
    Run Keyword If    '${operation}' == 'RESTART'    Restart Service    ${pod_name}    ${namespace}    ${pod_prefix}
    Run Keyword If    '${operation}' == 'UPGRADE' and '${controller}' == '${NONE}'    Upgrade Service    ${pod_prefix}
    Run Keyword If    '${operation}' == 'UPGRADE' and '${controller}' == 'ONOS'   Upgrade ONOS
    Run Keyword If    '${operation}' == 'UPGRADE' and '${controller}' == 'VOLTHA'   Upgrade VOLTHA
    Wait Until Keyword Succeeds    60s    2s    Subscriber Provisioned    ${server_ip}    ${src0['onu']}    ${src0['s_tag']}
    Wait Until Keyword Succeeds    60s    2s    Subscriber Service Chain Created    ${src0['onu']}    ${src0['s_tag']}
    Wait Until Keyword Succeeds    60s    2s    Check Ping    True    ${dst0['dp_iface_ip_qinq']}    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}   ${src0['container_type']}    ${src0['container_name']}

Get Pod Name
    [Arguments]    ${pod_prefix}
    ${rc}    ${namespace}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl get pods --all-namespaces | grep '${pod_prefix}' | head -1 | awk '{print $1}'
    ${rc}    ${pod_name}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl get pods --all-namespaces | grep '${pod_prefix}' | head -1 | awk '{print $2}'
    [Return]    ${pod_name}    ${namespace}

Restart Service
    [Arguments]    ${pod}    ${ns}    ${podprefix}
    Run    ${export_kubeconfig}; kubectl delete pod -n ${ns} ${pod}
    Wait Until Keyword Succeeds    60s    2s    Validate Pod Running    ${podprefix}    ${ns}

Validate Pod Running
    [Arguments]    ${pod}    ${ns}
    ${output}=    Run    ${export_kubeconfig}; kubectl get pods -n ${ns} | grep ${pod}
    Should Contain    ${output}    Running
    Should Contain    ${output}    1/1

Upgrade Service
    [Arguments]    ${service}
    ${rc}=    Run    ${export_kubeconfig}; kubectl delete pod $(kubectl get pods | grep seba-services-tosca | head -1 | awk '{print $1}')
    ${rc}=    Run    ${export_kubeconfig}; kubectl delete job $(kubectl get jobs | grep seba-services-tosca | head -1 | awk '{print $1}')
    ${rc}=    Run And Return RC    helm dep update ${HELM_CHARTS_DIR}/xos-profiles/seba-services
    Should Be Equal As Integers    ${rc}    0
    ${rc}=    Run And Return RC    helm upgrade --recreate-pods --set ${service}.image.tag=master seba-services ${HELM_CHARTS_DIR}/xos-profiles/seba-services
    Wait Until Keyword Succeeds    60s    5s    Validate Service Running    ${service}    1/1

Upgrade ONOS
    ${rc}=    Run And Return RC    helm upgrade --recreate-pods --set images.onos.tag=${onos_tag} onos ${HELM_CHARTS_DIR}/onos
    Should Be Equal As Integers    ${rc}    0
    Wait Until Keyword Succeeds    60s    5s    Validate Service Running    onos    2/2

Upgrade VOLTHA
    ${rc}=    Run And Return RC    helm dep update ${HELM_CHARTS_DIR}/voltha; helm upgrade --set images.vcore.tag=${voltha_tag} voltha ${HELM_CHARTS_DIR}/voltha
    Should Be Equal As Integers    ${rc}    0
    Wait Until Keyword Succeeds    60s    5s    Validate Voltha Running

Validate Voltha Running
    # wait for helm chart to be deployed
    ${output}=    Run    helm ls | grep voltha | grep -i deployed | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for the synchronizer pod to be running
    ${output}=    Run    kubectl get pods -n voltha | grep vcore | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for no other synchronizer pods to be terminating
    ${output}=    Run    kubectl get pods | grep vcore | grep -i terminating | wc -l
    Should Be Equal As Integers    ${output}    0

Validate Service Running
    [Arguments]    ${service}    ${pod_count}=1/1
    # wait for helm chart to be deployed
    ${output}=    Run    helm ls | grep seba-services | grep -i deployed | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for the synchronizer pod to be running
    ${output}=    Run    kubectl get pods | grep ${service} | grep -i running | grep ${pod_count} | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for no other synchronizer pods to be terminating
    ${output}=    Run    kubectl get pods | grep ${service} | grep -i terminating | wc -l
    Should Be Equal As Integers    ${output}    0

Clean Up Linux
    [Documentation]    Kill processes and clean up interfaces on src+dst servers
    Run Keyword And Ignore Error    Kill Linux Process    [w]pa_supplicant    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword And Ignore Error    Kill Linux Process    [d]hclient    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword If    '${dst0['ip']}' != '${None}'    Run Keyword And Ignore Error    Kill Linux Process    [d]hcpd    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}
    Delete IP Addresses from Interface on Remote Host    ${src0['dp_iface_name']}    ${src0['ip']}    ${src0['user']}    ${src0['pass']}    ${src0['container_type']}    ${src0['container_name']}
    Run Keyword If    '${dst0['ip']}' != '${None}'    Delete Interface on Remote Host    ${dst0['dp_iface_name']}.${src0['s_tag']}    ${dst0['ip']}    ${dst0['user']}    ${dst0['pass']}    ${dst0['container_type']}    ${dst0['container_name']}

