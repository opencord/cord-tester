# Copyright 2017-present Radisys Corporation
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
Documentation     Test suite for checking results collected by `make collect-diag` command
Library           OperatingSystem
Library           ../cord-api/Framework/utils/onosUtils.py
Library           ../cord-api/Framework/utils/utils.py
Resource          ../cord-api/Framework/utils/utils.robot

*** Variables ***
${DOCKER_CONTAINERS_FILE}       ${CURDIR}/dockerContainers.json
${ONOS_APPS_FILE}       	${CURDIR}/onosApps.json
${CORD_PROFILE}			rcord
${CORD_SCENARIO}		cord

*** Test Cases ***
Verify Docker Containers
    [Documentation]    Verify expected containers are up and running
    ${dockerContainersExpected}    utils.jsonToList    ${DOCKER_CONTAINERS_FILE}    docker-containers-${CORD_PROFILE}
    : FOR    ${container}    IN    @{dockerContainersExpected}
    \    OperatingSystem.File Should Exist    /home/cord/diag-*/docker/${container}

Verify Synchronizer Logs
    [Documentation]    Verify synchronizer logs are correct
    ${synchronizerLogs}    utils.readFiles    /home/cord/diag-*/docker/*synchronizer*
    : FOR    ${key}    IN    @{synchronizerLogs.keys()}
    \    ${value}=    Get From Dictionary    ${synchronizerLogs}    ${key}
    \    Should Contain    ${value}    Waiting for event or timeout

Verify ONOS
    [Documentation]    Verify ONOS status, applications and logs
    Run Keyword If    '${CORD_PROFILE}' != 'ecord-global'   Run Keywords
        Verify ONOS Status    onos-fabric
        Verify ONOS Applications    onos-fabric    ${CORD_PROFILE}
        Verify ONOS Logs    onos-fabric
    Verify ONOS Status    onos-cord
    Verify ONOS Applications    onos-cord   ${CORD_PROFILE}
    Verify ONOS Logs    onos-cord

*** Keywords ***
Verify ONOS Status
    [Arguments]    ${onosName}
    ${onosStatus}    utils.readFile    /home/cord/diag-*/${onosName}/nodes
    Should Contain    ${onosStatus}    READY

Verify ONOS Applications
    [Arguments]    ${onosName}    ${cordProfile}
    ${onosAppsExpected}    utils.jsonToList    ${ONOS_APPS_FILE}    ${onosName}-${cordProfile}
    ${onosApps}    utils.readFile    /home/cord/diag-*/${onosName}/apps_-s_-a
    : FOR    ${app}    IN    @{onosAppsExpected}
    \    Should Contain    ${onosApps}    ${app}

Verify ONOS Logs
    [Arguments]    ${onosName}
    ${onosLog}    utils.readFile    /home/cord/diag-*/${onosName}/log_display
    Should Not Contain    ${onosLog}    ERROR
