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
    \    Run Keyword And Continue On Failure    Verify Docker Container    ${container}

Verify Synchronizer Logs
    [Documentation]    Verify synchronizer logs are correct
    ${synchronizerLogs}    utils.readFiles    /home/cord/diag-*/docker/*synchronizer*
    : FOR    ${key}    IN    @{synchronizerLogs.keys()}
    \    @{nameWithSuffix}=    Split String    ${key}    cord_
    \    @{name}=    Split String    @{nameWithSuffix}[1]    -synchronizer
    \    ${synchronizerConfig}    utils.readFile    /opt/cord/orchestration/xos_services/*/xos/synchronizer/@{name}[0]_config.yaml
    \    ${synchronizerLog}=    Get From Dictionary    ${synchronizerLogs}    ${key}
    \    Run Keyword And Continue On Failure    Verify Synchronizer Log    ${synchronizerConfig}    ${synchronizerLog}

Verify ONOS
    [Documentation]    Verify ONOS status, applications and logs
    Run Keyword If    '${CORD_PROFILE}' != 'ecord-global'   Verify ONOS-Fabric    ${CORD_PROFILE}
    Verify ONOS-CORD    ${CORD_PROFILE}

*** Keywords ***
Verify Docker Container
    [Arguments]    ${container}
    OperatingSystem.File Should Exist    /home/cord/diag-*/docker/${container}

Verify Synchronizer Log
    [Arguments]    ${config}    ${log}
    Run Keyword If    'steps_dir' in '''${config}'''    Should Contain    ${log}    Waiting for event or timeout
    Run Keyword If    'model_policies_dir' in '''${config}'''    Should Contain    ${log}    Loaded model policies

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
