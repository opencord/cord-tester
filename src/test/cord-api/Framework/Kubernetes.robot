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
Library           utils/utils.py
Library           restApi.py
Resource          ../../Framework/utils/utils.robot

*** Keywords ***
Helm Chart is Removed
    [Arguments]    ${helm_chart}
    [Documentation]    Verify the specified helm chart has been removed
    ${rc}=    Run And Return Rc    ${export_kubeconfig}; helm ls -q | grep ${helm_chart}
    Should Be Equal As Integers    ${rc}    1

Kubernetes PODs in Namespace are Removed
    [Arguments]    ${namespace}
    [Documentation]    Verify all Kubernetes pods in specified namespace have been removed
    ${rc}    ${output}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl get pods --no-headers -n ${namespace}
    Should Contain    ${output}    No resources found

Kubernetes PODs in Namespace are Running
    [Arguments]    ${namespace}    ${pod_num}
    [Documentation]    Verify the number of Kubernetes pods that are running in specified namespace is as expected
    ${rc}    ${output}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl get pods -n ${namespace} | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    ${pod_num}

Reinstall Voltha
    Run    ${export_kubeconfig}; helm delete --purge voltha
    Wait Until Keyword Succeeds    60s    10s    Helm Chart is Removed    voltha
    Wait Until Keyword Succeeds    120s    10s    Kubernetes PODs in Namespace are Removed    voltha
    Run    ${export_kubeconfig}; cd ${HELM_CHARTS_DIR}; helm repo add incubator https://kubernetes-charts-incubator.storage.googleapis.com/
    Run    ${export_kubeconfig}; cd ${HELM_CHARTS_DIR}; helm dep up voltha
    Run    ${export_kubeconfig}; helm install -n voltha -f ${KUBERNETES_YAML} --set etcd-operator.customResources.createEtcdClusterCRD=false ${HELM_CHARTS_DIR}/voltha
    Run    ${export_kubeconfig}; helm upgrade -f ${KUBERNETES_YAML} --set etcd-operator.customResources.createEtcdClusterCRD=true voltha ${HELM_CHARTS_DIR}/voltha
    Wait Until Keyword Succeeds    60s    10s    Kubernetes PODs in Namespace are Running    voltha    ${VOLTHA_POD_NUM}
    Sleep    10s

Get Current Datetime On Kubernetes Node
    [Arguments]    ${ip}    ${user}    ${pass}
    ${result}=    Login And Run Command On Remote System    date +"%Y-%m-%dT%H:%M:%S.%NZ"    ${ip}    ${user}    ${pass}
    ${result}=    Get Line    ${result}    0
    [Return]    ${result}

Log Kubernetes Container Log Since Time
    [Arguments]    ${datetime}    ${container_name}
    ${rc}    ${output}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl logs --timestamps --since-time=${datetime} ${container_name}
    Log    ${output}

Log Kubernetes Containers Logs Since Time
    [Arguments]    ${datetime}    ${container_list}
    : FOR    ${container_name}    IN    @{container_list}
    \    Log Kubernetes Container Log Since Time     ${datetime}    ${container_name}

Get Kubernetes POD Name By Prefix
    [Arguments]    ${prefix}
    [Documentation]    Return the first POD name that starts with the specified prefix
    ${rc}    ${output}=    Run And Return Rc And Output    ${export_kubeconfig}; kubectl get pods --all-namespaces | grep '${prefix}' | head -1 | awk '{print $2}'
    [Return]    ${output}
