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
Documentation     Test suite to validate K8 pods in the experimental ControlKube Scenario
Library           OperatingSystem
Library           ../cord-api/Framework/utils/onosUtils.py
Library           ../cord-api/Framework/utils/utils.py
Resource          ../cord-api/Framework/utils/utils.robot

*** Variables ***
${CORD_PROFILE}               rcord
@{container_names_expected}    xos-db    xos-core

*** Test Cases ***
Validate K8 PODS
    [Documentation]    Validates that all containers that are running in the K8 Pods are healthy
    Log    Testing
    @{container_names}=    Create List
    Set Suite Variable    ${container_names}
    ${pods}=    Run    kubectl get pods -o json
    Log    ${pods}
    ${tmp}=    Get Json Value    ${pods}    /kind
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

Validate K8 Containers
    [Documentation]    Validates that all expected containers to be running are in one of the pods inspected above
    : FOR    ${i}    IN    @{container_names_expected}
    \    List Should Contain Value    ${container_names}    ${i}