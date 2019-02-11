*** Settings ***
Documentation     Rest migration test, unload services to return to clean slate
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Library           DateTime
Library           ../../Framework/utils/utils.py
Resource          ../../Framework/utils/utils.robot
Library           ../../Framework/restApi.py
Variables         ../../Properties/RestApiProperties.py
Suite Setup       Setup
Suite Teardown    Teardown
*** Variables ***
${timeout}    300s
*** Test Cases ***
Cleanup If Necessary
    [Tags]    test0
    [Documentation]    Cleanup from previous run. Not necessary during automation as there will be no previous run.
    Ensure Service Deleted
    Ensure Service Unloaded
*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json    allow_modify_feedback=True
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    @{model_A_fields}=    Create List    service_message    service_secret
    @{model_B_fields}=    Create List    service_message    service_secret    new_field
    @{model_B_only_fields}=    Create List    new_field
    Set Suite Variable    @{model_A_fields}
    Set Suite Variable    @{model_B_fields}
    Set Suite Variable    @{model_B_only_fields}
Teardown
    [Documentation]    Delete all https sessions
    Delete All Sessions
Ensure Service Deleted
    ${output}=    Run    helm ls | grep simpleexampleservice | grep -i deployed | wc -l
    Run Keyword If    ${output} == 1    Delete Service
Delete Service
    Log to Console    Deleating Service Helm Chart
    ${rc}=    Run And Return RC    helm del --purge simpleexampleservice
    Should Be Equal As Integers    ${rc}    0
    Log to Console    Deleted Service Helm Chart
Ensure Service Unloaded
    [Documentation]    Unload the service if it is loaded.
    Wait Until Keyword Succeeds    200s    2s    CORD Get    /xosapi/v1/core/users
    ${resp}=   Get Request    ${SERVER_IP}    uri=/xosapi/v1/dynamicload/load_status
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    ${length}=    Get Length   ${jsondata['services']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${dict}=    Get From List    ${jsondata['services']}    ${INDEX}
    \    Run Keyword If    "${dict['name']}" == "simpleexampleservice" and "${dict['state']}" == "present"    Unload Service
Unload Service
    [Documentation]    Unload the service
    Log To Console    Unloading Service
    ${data}=    Create Dictionary    name=simpleexampleservice    version=1.1.7
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    ${SERVER_IP}    uri=/xosapi/v1/dynamicload/unload_models    data=${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    Log To Console    Successfully Unloaded



