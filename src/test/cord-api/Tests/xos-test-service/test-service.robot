# XOS Core Test
#
# This test will validate the xos-core's sync steps and model policies using the TestService
#

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
${testservice_api}             /xosapi/v1/testservice/testserviceservices
${testservice_si}              /xosapi/v1/testservice/testserviceserviceinstances
${testservice_duplicate_si}    /xosapi/v1/testservice/testserviceduplicateserviceinstances

*** Test Cases ***
Create Test Model with No Duplicate
    [Documentation]    Create a testservice service instance with no duplicate
    [Tags]    create
    ${model_name}=    Generate Random Value    string
    ${data}=    Create Dictionary    name=${model_name}    create_duplicate=${false}
    ${resp}=    CORD Post    ${testservice_si}     ${data}
    ${json_content}=    To Json    ${resp.content}
    ${test_serviceinstance_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${test_serviceinstance_id}
    Set Suite Variable    ${model_name}
    Repeat Keyword    10s    Validate Duplicate Model    false

Update Model with Duplicate
    [Tags]    update
    CORD Put    ${testservice_si}     {'create_duplicate': ${true}}    ${test_serviceinstance_id}
    Wait Until Keyword Succeeds    60s    2s    Validate Duplicate Model    true

Revert Model
    [Tags]    revert    notready
    CORD Put    ${testservice_si}     {'create_duplicate': ${false}}    ${test_serviceinstance_id}
    Wait Until Keyword Succeeds    60s    2s    Validate Duplicate Model    false

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json    allow_modify_feedback=True
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    # create test-service
    ${data}=    Create Dictionary    name=xos-core-test-service-test
    ${resp}=    CORD Post    ${testservice_api}    ${data}

Teardown
    [Documentation]    Delete all https sessions
    Clean Up Objects    ${testservice_si}
    Clean Up Objects    ${testservice_duplicate_si}
    Clean Up Objects    ${testservice_api}
    Delete All Sessions

Validate Duplicate Model
    [Documentation]    Checks if 'testserviceduplicateserviceinstances' was created or not
    [Arguments]    ${exists}=false
    ${resp}=    Wait Until Keyword Succeeds    60s    2s    CORD Get    ${testservice_duplicate_si}
    ${jsondata}=    To Json    ${resp.content}
    Run Keyword If    '${exists}' == 'false'    Should Be Empty    ${jsondata['items']}    ELSE    Verify Exists    ${jsondata}

Verify Exists
    [Arguments]    ${data}
    ${dict}=    Get From List    ${data['items']}    0
    Should Be Equal As Strings    ${dict['name']}    ${model_name}
