# Copyright 2018-present Open Networking Foundation
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
Suite Setup       Setup
Suite Teardown    Teardown
Test Timeout      10 minutes
Documentation     Validates onboarding/deleting of TOSCA Recipies
Library           OperatingSystem
Library           /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/utils.py
Library           /opt/cord/test/cord-tester/src/test/cord-api/Framework/restApi.py
Resource          /opt/cord/test/cord-tester/src/test/cord-api/Framework/utils/utils.robot
Variables         /opt/cord/test/cord-tester/src/test/cord-api/Properties/RestApiProperties.py


*** Variables ***
${site_template}    ${CURDIR}/templates/CordTesterSite.yml

*** Test Cases ***
Onboard Test
    [Documentation]    Onboards a site template via tosca and veriifies
    [Tags]    run
    TOSCA Load    run    ${site_template}
    Wait Until Keyword Succeeds    10s    1s    Valiate Operation via REST    created    ${CH_CORE_SITES}    mysitecordtester

Delete Test
    [Documentation]    Deletes the site template via tosca and veriifies
    [Tags]    delete
    TOSCA Load    delete    ${site_template}
    Wait Until Keyword Succeeds    10s    1s    Valiate Operation via REST    deleted    ${CH_CORE_SITES}    mysitecordtester

*** Keywords ***
Setup
    Log    Setting up
    ${auth} =    Create List    ${USER}    ${PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${SERVER_IP}    http://${SERVER_IP}:${SERVER_PORT}    auth=${AUTH}    headers=${HEADERS}

Teardown
    Log    Tearing down
    Delete All Sessions

TOSCA Load
    [Documentation]    Make a call to the XOS-TOSCA service
    [Arguments]    ${operation}    ${data_file}
    ${status_code}=    Run    curl -s -o /dev/null -w "\%{http_code}" -H "xos-username:${USER}" -H "xos-password:${PASSWD}" -X POST --data-binary @${data_file} http://localhost/xos-tosca/${operation}
    Should Be Equal As Integers    ${status_code}    200

CORD Get
    [Documentation]    Make a GET call to the CORD controller
    [Arguments]    ${session}    ${service}
    ${resp}=    Get Request    ${session}    ${service}
    Log    ${resp.content}
    [Return]    ${resp}

Valiate Operation via REST
    [Documentation]    Check is object exists via XOS REST API
    [Arguments]    ${state}    ${endpoint}    ${value}
    ${resp}=    CORD GET    ${SERVER_IP}    ${endpoint}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    @{names}=    Create List
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${item}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${name}=    Get From Dictionary    ${item}    name
    \    Append To List    ${names}    ${name}
    Run Keyword If    '${state}' == 'created'    List Should Contain Value    ${names}    ${value}
    Run Keyword If    '${state}' == 'deleted'    List Should Not Contain Value    ${names}    ${value}