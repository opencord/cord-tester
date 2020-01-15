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
Documentation     Library of functions related to kubectl and helm
Library           SSHLibrary
Library           Collections
Library           String
Library           OperatingSystem
Library           RequestsLibrary
Library           CORDRobot
Resource          utils.resource

*** Keywords ***
Helm Chart is Removed
    [Documentation]    Verify the specified helm chart has been removed
    [Arguments]    ${helm_chart}
    ${rc}=    Run And Return Rc
    ...    helm ls -q | grep ${helm_chart}
    Should Be Equal As Integers    ${rc}    1

Kubernetes PODs in Namespace are Removed
    [Documentation]    Verify all Kubernetes pods in specified namespace have been removed
    [Arguments]    ${namespace}
    ${rc}    ${output}=    Run And Return Rc And Output
    ...    kubectl get pods --no-headers -n ${namespace}
    Should Contain    ${output}    No resources found

Kubernetes PODs in Namespace are Running
    [Documentation]    Verify the number of Kubernetes pods that are running
    ...    in specified namespace is as expected
    [Arguments]    ${namespace}    ${pod_num}
    ${rc}    ${output}=    Run And Return Rc And Output
    ...    kubectl get pods -n ${namespace} | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    ${pod_num}

Reinstall Voltha
    [Documentation]    Remove voltha helm chart and wait
    Run    helm delete --purge voltha
    Wait Until Keyword Succeeds    60s    10s
    ...    Helm Chart is Removed    voltha
    Wait Until Keyword Succeeds    120s    10s
    ...    Kubernetes PODs in Namespace are Removed    voltha
    Sleep    10s
    Run    helm repo add incubator https://kubernetes-charts-incubator.storage.googleapis.com/
    # FIXME - HELM_CHARTS_DIR should a parameter
    Run    cd ${HELM_CHARTS_DIR}; helm dep up voltha
    # FIXME - KUBERNETES_YAML should a parameter
    Run    helm install -n voltha -f ${KUBERNETES_YAML} ${HELM_CHARTS_DIR}/voltha
    Wait Until Keyword Succeeds    60s    10s
    ...    Kubernetes PODs in Namespace are Running    voltha    ${VOLTHA_POD_NUM}
    Sleep    10s

Get Current Datetime On Kubernetes Node
    [Documentation]    Get UTC datetime in RFC3339ish format
    [Arguments]    ${ip}    ${user}    ${pass}
    ${result}=    Login And Run Command On Remote System
    ...    date -u +"%Y-%m-%dT%H:%M:%S.%NZ"    ${ip}    ${user}    ${pass}
    # FIXME - is this needed? Does date return multiple lines?
    ${result}=    Get Line    ${result}    0
    [Return]    ${result}

Log Kubernetes Container Log Since Time
    [Documentation]    Returns the output of kubectl logs of a pod since timestamp
    [Arguments]    ${datetime}    ${pod_prefix}
    # FIXME - rc var isn't checked and then overwritten in this set of commands
    ${rc}    ${namespace}=    Run And Return Rc And Output
    ...    kubectl get pods --all-namespaces | grep ' ${pod_prefix}' | head -1 | awk '{print $1}'
    ${rc}    ${pod_name}=    Run And Return Rc And Output
    ...    kubectl get pods --all-namespaces | grep ' ${pod_prefix}' | head -1 | awk '{print $2}'
    ${rc}    ${output}=    Run Keyword If    '${pod_prefix}' == 'onos'
    ...    Run And Return Rc And Output
    ...    kubectl logs --timestamps -n ${namespace} --since-time=${datetime} ${pod_name} -c onos
    ...    ELSE    Run And Return Rc And Output
    ...    kubectl logs --timestamps -n ${namespace} --since-time=${datetime} ${pod_name}
    Log    ${output}

Log Kubernetes Containers Logs Since Time
    [Documentation]    Given a datetime and list of containers, print logs for those containers
    [Arguments]    ${datetime}    ${pod_list}
    FOR    ${pod_prefix}    IN    @{pod_list}
        Log Kubernetes Container Log Since Time    ${datetime}    ${pod_prefix}
    END

Get Kubernetes POD Name By Prefix
    [Documentation]    Return the first POD name that starts with the specified prefix
    [Arguments]    ${prefix}
    ${rc}    ${output}=    Run And Return Rc And Outputi
    ...    kubectl get pods --all-namespaces | grep '${prefix}' | head -1 | awk '{print $2}'
    [Return]    ${output}
