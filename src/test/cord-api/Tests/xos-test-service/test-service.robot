
# XOS Core Test
#
# This test will validate the xos-core's sync steps and model policies using the TestService
#

*** Settings ***
Documentation     Test migration of a Service in the core
Library           RequestsLibrary
Library           Collections
Library           String
Library           OperatingSystem
Library           DateTime
Library           CORDRobot
Library           ImportResource  resources=CORDRobot
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
    ${default_float}=    Get From Dictionary    ${json_content}    optional_float_with_default
    ${default_string}=    Get From Dictionary    ${json_content}    optional_string_with_default
    ${default_int}=    Get From Dictionary    ${json_content}    optional_int_with_default
    Set Suite Variable    ${test_serviceinstance_id}
    Set Suite Variable    ${model_name}
    Set Suite Variable    ${default_float}
    Set Suite Variable    ${default_string}
    Set Suite Variable    ${default_int}
    Repeat Keyword    10s    Validate Duplicate Model    false

Replicate Model with Duplicate
    [Tags]    replicate
    CORD Put    ${testservice_si}     {'create_duplicate': ${true}}    ${test_serviceinstance_id}
    Wait Until Keyword Succeeds    15s    2s    Validate Duplicate Model    true

Update Model Values and Validate on Duplicate
    [Tags]    update
    ##create optional strings
    @{choices}=    Create List    one    two
    ${optional_string}=    Generate Random Value    string    max_length=50
    ${optional_string_choice}=    Evaluate    random.choice($choices)    random
    ${optional_string_max_length}=    Generate Random Value    string    max_length=32
    ${optional_string_date}=    Get Current Date    result_format=%m-%d-%Y
    ${optional_string_ip}=    Generate Random Value    ip_address
    ##create optional ints
    @{choices}=    Create List    one    two
    ${optional_integer_min}=    Generate Random Value    int32    min_int=100
    ${optional_integer_max}=    Generate Random Value    int32    max_int=199
    ${optional_string_choice}=    Evaluate    random.choice($choices)    random
    ${optional_string_max_length}=    Generate Random Value    string    max_length=32
    #${optional_string_max}=    Get Substring    ${optional_string_max_length}    0    32
    ${optional_string_date}=    Get Current Date    result_format=%m-%d-%Y
    ${optional_string_ip}=    Generate Random Value    ip_address
    ##create optional float
    ${optional_float}=    Generate Random Value    float
    Set Suite Variable    ${optional_string}
    Set Suite Variable    ${optional_string_choice}
    Set Suite Variable    ${optional_string_max_length}
    Set Suite Variable    ${optional_string_date}
    Set Suite Variable    ${optional_string_ip}
    Set Suite Variable    ${optional_integer_min}
    Set Suite Variable    ${optional_integer_max}
    Set Suite Variable    ${optional_float}
    ${data}=    Create Dictionary    optional_string=${optional_string}
    Set To Dictionary    ${data}    optional_string_with_choices=${optional_string_choice}
    Set To Dictionary    ${data}    optional_string_max_length=${optional_string_max_length}
    #Set To Dictionary    ${data}    optional_string_date=${optional_string_date}
    Set To Dictionary    ${data}    optional_string_ip=${optional_string_ip}
    Set To Dictionary    ${data}    optional_int_with_min=${optional_integer_min}
    Set To Dictionary    ${data}    optional_int_with_max=${optional_integer_max}
    Set To Dictionary    ${data}    optional_float=${optional_float}
    CORD Put    ${testservice_si}    ${data}    ${test_serviceinstance_id}
    Wait Until Keyword Succeeds    60s    2s    Validate Duplicate Model with Updates

Revert Model
    [Tags]    revert
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
    Should Be Equal As Strings    ${dict['optional_float_with_default']}    ${default_float}
    Should Be Equal As Strings    ${dict['optional_string_with_default']}    ${default_string}
    Should Be Equal As Strings    ${dict['optional_int_with_default']}    ${default_int}

Validate Duplicate Model with Updates
    ${resp}=    CORD Get    ${testservice_duplicate_si}
    ${jsondata}=    To Json    ${resp.content}
    ${dict}=    Get From List    ${jsondata['items']}    0
    Should Be Equal As Strings    ${dict['name']}    ${model_name}
    Should Be Equal As Strings    ${dict['optional_float_with_default']}    ${default_float}
    Should Be Equal As Strings    ${dict['optional_string_with_default']}    ${default_string}
    Should Be Equal As Strings    ${dict['optional_int_with_default']}    ${default_int}
    Should Be Equal As Strings    ${dict['optional_string']}    ${optional_string}
    Should Be Equal As Strings    ${dict['optional_string_with_choices']}    ${optional_string_choice}
    Should Be Equal As Strings    ${dict['optional_string_max_length']}    ${optional_string_max_length}
    Should Be Equal As Strings    ${dict['optional_string_ip']}    ${optional_string_ip}
    Should Be Equal As Strings    ${dict['optional_int_with_min']}    ${optional_integer_min}
    Should Be Equal As Strings    ${dict['optional_int_with_max']}    ${optional_integer_max}
    ${float_diff}=    Evaluate    abs(${optional_float} - ${dict['optional_float']})
    Should Be True    ${float_diff} < .0005
