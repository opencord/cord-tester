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

# NOTE: `make collect-diag` command needs to be executed on the head-node
#        before running this test

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
    \    Run Keyword And Continue On Failure    Verify Docker Container    ${container}

Verify Synchronizer Logs
    [Documentation]    Verify synchronizer logs are correct
    ${latestDiag}=    Run    ls -1t /home/cord | head -1
    ${synchronizerLogs}    utils.readFiles    /home/cord/${latestDiag}/docker/*synchronizer*.logs
    : FOR    ${key}    IN    @{synchronizerLogs.keys()}
    \    @{name}=    Split String    ${key}    -synchronizer
    \    @{name}=    Split String From Right   @{name}[0]    _    1
    \    ${synchronizerLog}=    Get From Dictionary    ${synchronizerLogs}    ${key}
    \    Run Keyword And Continue On Failure    Verify Synchronizer Log    ${name}    ${synchronizerLog}

Verify ONOS
    [Documentation]    Verify ONOS status, applications and logs
    Run Keyword If    '${CORD_PROFILE}' != 'ecord-global'   Verify ONOS-Fabric    ${CORD_PROFILE}
    Verify ONOS-CORD    ${CORD_PROFILE}

*** Keywords ***
Verify Docker Container
    [Arguments]    ${container}
    OperatingSystem.File Should Exist    /home/cord/diag-*/docker/${container}.logs

Verify Synchronizer Log
    [Arguments]    ${name}    ${log}
    ${config}    utils.readFile    /opt/cord/orchestration/*/*/xos/synchronizer/@{name}[1]_config.yaml
    ${match1}=    Get Lines Matching Regexp    ${config}    ^steps_dir: ".*"$
    ${match2}=    Get Lines Matching Regexp    ${config}    ^model_policies_dir: ".*"$
    Run Keyword If    '${match1}' != '${EMPTY}'    Should Contain    ${log}    Waiting for event or timeout    msg= "Waiting for event or timeout" not found in @{name}[1] synchronizer log
    ...    ELSE IF    '${match2}' != '${EMPTY}'    Should Contain    ${log}    Loaded model policies    msg= "Loaded model policies" not found in @{name}[1] synchronizer log

Verify ONOS-Fabric
    [Arguments]    ${cord_profile}
    Run Keyword And Continue On Failure    Verify ONOS Status    onos-fabric
    Run Keyword And Continue On Failure    Verify ONOS Applications    onos-fabric    ${cord_profile}
    Run Keyword And Continue On Failure    Verify ONOS Log    onos-fabric

Verify ONOS-CORD
    [Arguments]    ${cord_profile}
    Run Keyword And Continue On Failure    Verify ONOS Status    onos-cord
    Run Keyword And Continue On Failure    Verify ONOS Applications    onos-cord    ${cord_profile}
    Run Keyword And Continue On Failure    Verify ONOS Log    onos-cord

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

Verify ONOS Log
    [Arguments]    ${onosName}
    ${onosLog}    utils.readFile    /home/cord/diag-*/${onosName}/log_display
    Should Not Contain    ${onosLog}    ERROR
