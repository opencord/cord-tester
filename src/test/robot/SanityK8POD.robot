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
Suite Setup       Setup
Library           OperatingSystem
Library           ../cord-api/Framework/utils/onosUtils.py
Library           ../cord-api/Framework/utils/utils.py
Resource          ../cord-api/Framework/utils/utils.robot

*** Variables ***
${profile}           rcord-lite
${deployment}        virtual
@{physical_nodes}    head1    compute1    compute2
@{minikube_nodes}    minikube
${resources_file}    ${CURDIR}/data/k8resources.json


*** Test Cases ***
Validate K8 Nodes
    [Documentation]    Validates that all nodes that are running in the K8 are healthy
    [Tags]    xos-core
    ${nodes}=    Run    kubectl get nodes -o json
    Log    ${nodes}
    @{nodes}=    Get Names    ${nodes}
    ##set nodes based on deployment
    @{nodes_expected}=    Set Variable If    '${deployment}' == 'physical'    ${physical_nodes}    ${minikube_nodes}
    Log    ${nodes_expected}
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

Validate XOS Core Containers
    [Documentation]    Validates that all xos core containers that are running in the K8 Pods are healthy
    [Tags]    xos-core
    @{core_container_names}=    Run Keyword and Continue on Failure    Validate Pods    xos-
    #validates that all expected containers to be running are in one of the pods inspected above
    : FOR    ${i}    IN    @{core_containers}
    \    Run Keyword and Continue on Failure    List Should Contain Value    ${core_container_names}    ${i}

Validate RCord-Lite Containers
    [Documentation]    Validates that all rcord-lite containers that are running in the K8 Pods are healthy
    [Tags]    rcord-lite
    @{rcord_container_names}=    Run Keyword and Continue on Failure    Validate Pods    rcord-lite-
    #validates that all expected containers to be running are in one of the pods inspected above
    : FOR    ${i}    IN    @{rcord_lite_containers}
    \    Run Keyword and Continue on Failure    List Should Contain Value    ${rcord_container_names}    ${i}

Validate ONOS-Fabric Containers
    [Documentation]    Validates that all onos-fabric containers that are running in the K8 Pods are healthy
    [Tags]    onos-fabric
    @{onos_container_names}=    Run Keyword and Continue on Failure    Validate Pods    onos-fabric
    #validates that all expected containers to be running are in one of the pods inspected above
    : FOR    ${i}    IN    @{onos_fabric_containers}
    \    Run Keyword and Continue on Failure    List Should Contain Value    ${onos_container_names}    ${i}

Validate XOS Core Deployments
    [Documentation]    Validates that all xos-core deployments successfully rolled out and available
    [Tags]    deployments    xos-core
    Validate Deployments    xos-    ${core_deployments}

Validate RCord-Lite Deployments
    [Documentation]    Validates that all rcord-lite deployments successfully rolled out and available
    [Tags]    deployments    rcord-lite
    Validate Deployments    rcord-lite-    ${rcord_lite_deployments}

Validate ONOS-Fabric Deployments
    [Documentation]    Validates that all onos-fabric deployments successfully rolled out and available
    [Tags]    deployments    onos-fabric
    Validate Deployments    onos-fabric    ${onos_fabric_deployments}

Validate XOS Core Services
    [Documentation]    Validates that all expected xos-core services that are running in K8s
    [Tags]    services    xos-core
    ${services}=    Run    kubectl get services -o json
    Log    ${services}
    @{services}=    Get Names    ${services}
    #validates that all expected services are running
    : FOR    ${i}    IN    @{xos_core_services}
    \    Run Keyword and Continue on Failure    List Should Contain Value    ${services}    ${i}
    ##check for appropriate ports for each service and match with values in helm charts
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].port}'
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].targetPort}'

Validate ONOS-Fabric Services
    [Documentation]    Validates that all expected onos-fabric services that are running in K8s
    [Tags]    services    onos-fabric
    ${services}=    Run    kubectl get services -o json
    Log    ${services}
    @{services}=    Get Names    ${services}
    #validates that all expected services are running
    : FOR    ${i}    IN    @{onos_fabric_services}
    \    Run Keyword and Continue on Failure    List Should Contain Value    ${services}    ${i}
    ##check for appropriate ports for each service and match with values in helm charts
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].port}'
    ## eg. kubectl get svc xos-core -o jsonpath='{.spec.ports[?(@.name=="secure")].targetPort}'

*** Keywords ***
Setup
    Log    Setting up
    @{core_containers}=    Create List
    @{rcord_lite_containers}=    Create List
    @{onos_fabric_containers}=    Create List
    @{core_deployments}=    Create List
    @{rcord_lite_deployments}=    Create List
    @{onos_fabric_deployments}=    Create List
    @{xos_core_services}=    Create List
    @{onos_fabric_services}=    Create List
    ${xos-core_containers}    utils.jsonToList    ${resources_file}    xos-core-containers
    : FOR    ${container}    IN    @{xos-core_containers}
    \    Append To List    ${core_containers}    ${container}
    ${rcord_containers}    utils.jsonToList    ${resources_file}    rcord-lite-containers
    : FOR    ${container}    IN    @{rcord_containers}
    \    Append To List    ${rcord_lite_containers}    ${container}
    ${onosfabric_containers}    utils.jsonToList    ${resources_file}    onos-fabric-containers
    : FOR    ${container}    IN    @{onosfabric_containers}
    \    Append To List    ${onos_fabric_containers}    ${container}
    ${xos-core_deployments}    utils.jsonToList    ${resources_file}    xos-core-deployments
    : FOR    ${deployment}    IN    @{xos-core_containers}
    \    Append To List    ${core_deployments}    ${deployment}
    ${rcord_deployments}    utils.jsonToList    ${resources_file}    rcord-lite-deployments
    : FOR    ${deployment}    IN    @{rcord_deployments}
    \    Append To List    ${rcord_lite_deployments}    ${deployment}
    ${onosfabric_deployments}    utils.jsonToList    ${resources_file}    rcord-lite-deployments
    : FOR    ${deployment}    IN    @{onosfabric_deployments}
    \    Append To List    ${onos_fabric_deployments}    ${deployment}
    ${core_services}    utils.jsonToList    ${resources_file}    xos-core-services
    : FOR    ${service}    IN    @{core_services}
    \    Append To List    ${xos_core_services}    ${service}
    ${onos_services}    utils.jsonToList    ${resources_file}    onos-fabric-services
    : FOR    ${service}    IN    @{onos_services}
    \    Append To List    ${onos_fabric_services}    ${service}
    Set Suite Variable    @{core_containers}
    Set Suite Variable    @{rcord_lite_containers}
    Set Suite Variable    @{onos_fabric_containers}
    Set Suite Variable    @{core_deployments}
    Set Suite Variable    @{rcord_lite_deployments}
    Set Suite Variable    @{onos_fabric_deployments}
    Set Suite Variable    @{xos_core_services}
    Set Suite Variable    @{onos_fabric_services}

Teardown
    Log    Tearing down

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

Validate Pods
    [Arguments]    ${component}
    @{container_names}=    Create List
    ${pods}=    Run    kubectl get pods -o json
    Log    ${pods}
    ${pods}=    To JSON    ${pods}
    ${len}=    Get Length    ${pods}
    ${length}=    Get Length    ${pods['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${item}=    Get From List    ${pods['items']}    ${INDEX}
    \    ${metadata}=    Get From Dictionary    ${item}    metadata
    \    ${name}=    Get From Dictionary    ${metadata}    name
    \    Continue For Loop If    '${component}' not in '''${name}'''
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
    [Return]    ${container_names}

Validate Deployments
    [Arguments]    ${component}    ${expected_deployments}
    ${deployments}=    Run    kubectl get deployments -o json
    @{deployments}=    Get Names    ${deployments}
    : FOR    ${i}    IN    @{deployments}
    \    Continue For Loop If    '${component}' not in '''${i}'''
    \    ${rollout_status}=    Run    kubectl rollout status deployment/${i}
    \    Should Be Equal    ${rollout_status}    deployment "${i}" successfully rolled out
    \    ##validate replication sets
    \    ${desired}=    Run    kubectl get deployments ${i} -o jsonpath='{.status.replicas}'
    \    ${available}=    Run    kubectl get deployments ${i} -o jsonpath='{.status.availableReplicas}'
    \    Should Be Equal    ${desired}    ${available}
    #validates that all expected deployments to exist
    : FOR    ${i}    IN    @{expected_deployments}
    \    List Should Contain Value    ${deployments}    ${i}