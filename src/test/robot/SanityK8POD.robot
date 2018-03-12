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
Documentation     Test suite to validate K8s in the experimental ControlKube Scenario
Library           OperatingSystem
Library           ../cord-api/Framework/utils/onosUtils.py
Library           ../cord-api/Framework/utils/utils.py
Resource          ../cord-api/Framework/utils/utils.robot

*** Variables ***
${CORD_PROFILE}                rcord
@{containers_expected}    xos-db    xos-core
@{nodes_expected}              head1    compute1    compute2
@{deployments_expected}         xos-db    xos-core
@{services_expected}             kubernetes    xos-core    xos-db

*** Test Cases ***
Validate K8 Deployments
    [Documentation]    Validates that all nodes that are running in the K8 are healthy
    ${deployments}=    Run    kubectl get deployments -o json
    Log    ${deployments}
    @{deployments}=    Get Names    ${deployments}
    #validates that all expected deployments to exist
    : FOR    ${i}    IN    @{deployments_expected}
    \    List Should Contain Value    ${deployments}    ${i}
    : FOR    ${i}    IN    @{deployments}
    \    ${rollout_status}=    Run    kubectl rollout status deployment/${i}
    \    Should Be Equal    ${rollout_status}    deployment "${i}" successfully rolled out
    \    ##validate replication sets
    \    ${desired}=    Run    kubectl get deployments ${i} -o jsonpath='{.status.replicas}'
    \    ${available}=    Run    kubectl get deployments ${i} -o jsonpath='{.status.availableReplicas}'
    \    Should Be Equal    ${desired}    ${available}

Validate K8 Pods External Connectivity
    [Documentation]    Validates that all pods have external connectivity
    ${pods}=    Run    kubectl get pods -o json
    Log    ${pods}
    @{pods}=    Get Names    ${pods}
    Set Suite Variable    @{pods}
    : FOR    ${i}    IN    @{pods}
    \    ${ping_result}=    Run    kubectl exec -t -i ${i} -- ping -w 3 8.8.8.8
    \    Should Contain    ${ping_result}    64 bytes
    \    Should Not Contain    ${ping_result}    Destination Host Unreachable

Validate K8 Pods Cluster Networking
    [Documentation]    Validates that pods can reach each other
    ${kube_system_ip}=    Run    kubectl get pods --namespace=kube-system -o jsonpath='{.items[0].status.podIP}'
    : FOR    ${i}    IN    @{pods}
    \    ${pod_ip}=    Run    kubectl get pods --namespace=default xos-core-7fc8966fb9-kkqrv -o jsonpath='{.status.podIP}'
    \    ${ping_result}=    Run    kubectl exec -t -i ${i} -- ping -w 3 ${kube_system_ip}
    \    Log To Console    \n ${ping_result}
    \    Should Contain    ${ping_result}    64 bytes
    \    Should Not Contain    ${ping_result}    Destination Host Unreachable

Validate K8 Services
    [Documentation]    Validates that all expected services that are running in K8s
    ${services}=    Run    kubectl get services -o json
    Log    ${services}
    @{services}=    Get Names    ${services}
    #validates that all expected services are running
    : FOR    ${i}    IN    @{services_expected}
    \    List Should Contain Value    ${services}    ${i}
    ##check for appropriate ports for each service and match with values in helm charts
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].port}'
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].targetPort}'

Validate K8 Nodes
    [Documentation]    Validates that all nodes that are running in the K8 are healthy
    ${nodes}=    Run    kubectl get nodes -o json
    Log    ${nodes}
    @{nodes}=    Get Names    ${nodes}
    #validates that all expected nodes to be running
    : FOR    ${i}    IN    @{nodes_expected}
    \    List Should Contain Value    ${nodes}    ${i}
    : FOR    ${i}    IN    @{nodes}
    \    ${status}=     Run    kubectl get nodes ${i} -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
    \    ${outofdisk}=     Run    kubectl get nodes ${i} -o jsonpath='{.status.conditions[?(@.type=="OutOfDisk")].status}'
    \    ${memorypressure}=     Run    kubectl get nodes ${i} -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}'
    \    ${diskpressure}=     Run    kubectl get nodes ${i} -o jsonpath='{.status.conditions[?(@.type=="DiskPressure")].status}'
    \    Should Be Equal    ${status}    True
    \    Should Be Equal    ${outofdisk}    False
    \    Should Be Equal    ${memorypressure}    False
    \    Should Be Equal    ${diskpressure}    False

Validate K8 Containers
    [Documentation]    Validates that all containers that are running in the K8 Pods are healthy
    @{container_names}=    Create List
    ${pods}=    Run    kubectl get pods -o json
    Log    ${pods}
    ${pods}=    To JSON    ${pods}
    ${len}=    Get Length    ${pods}
    ${length}=    Get Length    ${pods['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${item}=    Get From List    ${pods['items']}    ${INDEX}
    \    ${status}=    Get From Dictionary    ${item}    status
    \    ${containerStatuses}=    Get From Dictionary    ${status}    containerStatuses
    \    Log    ${containerStatuses}
    \    ${cstatus}=    Get From List    ${containerStatuses}    0
    \     Log    ${cstatus}
    \    ${restartCount}=    Get From Dictionary    ${cstatus}    restartCount
    \    Should Be Equal As Integers    ${restartCount}    0
    \    ${container_name}=    Get From Dictionary    ${cstatus}    name
    \    ${state}=    Get From Dictionary    ${cstatus}    state
    \    Should Contain    ${state}    running
    \    Should Not Contain    ${state}    stopped
    \    Log    ${state}
    \    Append To List    ${container_names}    ${container_name}
    #validates that all expected containers to be running are in one of the pods inspected above
    : FOR    ${i}    IN    @{containers_expected}
    \    List Should Contain Value    ${container_names}    ${i}

*** Keywords ***
Get Names
    [Documentation]    Gets names of K8 resources running
    [Arguments]    ${output}
    @{names}=    Create List
    ${output}=    To JSON    ${output}
    ${len}=    Get Length    ${output}
    ${length}=    Get Length    ${output['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${item}=    Get From List    ${output['items']}    ${INDEX}
    \    ${metadata}=    Get From Dictionary    ${item}    metadata
    \    ${name}=    Get From Dictionary    ${metadata}    name
    \    Append To List    ${names}    ${name}
    [Return]    @{names}