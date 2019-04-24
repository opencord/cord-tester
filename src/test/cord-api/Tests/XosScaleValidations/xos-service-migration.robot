*** Settings ***
Documentation     Test migration of a Service in the core
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
Validate Service Version A
    [Documentation]    Validate fields from model in version A
    [Tags]    test1
    ${resp} =   CORD Get    /xosapi/v1/core/users
    ${jsondata} =    To Json    ${resp.content}
    ${length} =    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${dict}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${keys}=    Get Dictionary Keys    ${dict}
    : FOR    ${field}    IN    @{model_A_fields}
    \    List Should Contain Value    ${keys}    ${field}

Upgrade Service
    [Documentation]    Upgrade the version of the service and wait for completion
    [Tags]    test2
    Run    helm upgrade --set imageTag=2.0.0 demosimpleexampleservice
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Pod Running

Validate Service Version B
    [Documentation]    Validate fields from model in upgraded version B (2.0.0)
    [Tags]    test3
    ${resp} =   CORD Get    /xosapi/v1/core/users
    ${jsondata} =    To Json    ${resp.content}
    ${length} =    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${dict}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${keys}=    Get Dictionary Keys    ${dict}
    : FOR    ${field}    IN    @{model_B_fields}
    \    List Should Contain Value    ${keys}    ${field}

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json    allow_modify_feedback=True
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    @{model_A_fields}=    Create List    firstname    lastname    timezone
    @{model_B_fields}=    Create List    firstname    lastname    timezone    newBfield
    Set Suite Variable    @{model_A_fields}
    Set Suite Variable    @{model_B_fields}

Teardown
    [Documentation]    Delete all https sessions
    Delete All Sessions

Validate Pod Running
    ${output}=    Run    kubectl get pods | grep demo-simpleexampleservice | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    1
