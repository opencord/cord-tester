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

*** Keywords ***
Helm Chart is Removed
    [Arguments]    ${kubernetes_conf}    ${helm_chart}
    [Documentation]    Verify the specified helm chart has been removed
    Run    export KUBECONFIG=${kubernetes_conf}
    ${rc}=    Run And Return Rc    helm ls -q | grep ${helm_chart}
    Should Be Equal As Integers    ${rc}    1

Kubernetes PODs in Namespace are Removed
    [Arguments]    ${kubernetes_conf}    ${namespace}
    [Documentation]    Verify all Kubernetes pods in specified namespace have been removed
    Run    export KUBECONFIG=${kubernetes_conf}
    ${rc}    ${output}=    Run And Return Rc And Output    kubectl get pods --no-headers -n ${namespace}
    Should Contain    ${output}    No resources found

Kubernetes PODs in Namespace are Running
    [Arguments]    ${kubernetes_conf}    ${namespace}    ${pod_num}
    [Documentation]    Verify the number of Kubernetes pods that are running in specified namespace is as expected
    Run    export KUBECONFIG=${kubernetes_conf}
    ${rc}    ${output}=    Run And Return Rc And Output    kubectl get pods -n ${namespace} | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    ${pod_num}
