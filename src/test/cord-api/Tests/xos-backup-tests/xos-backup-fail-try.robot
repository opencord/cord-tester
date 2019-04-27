# XOS Backup Tests
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
${timeout}    300s
${cleanup}    ${true}

*** Test Cases ***
Create BackupFile
    [Documentation]    Create a backupfile model
    [Tags]    test1
    ${file_name}=    Generate Random Value    string
    ${file_uri}=     Catenate    SEPARATOR=    file:///var/run/xos/backup/local/    fail_try_models_    ${file_name}
    ${data}=    Create Dictionary    name=${file_name}    uri=${file_uri}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupfiles    ${data}
    ${json_content}=    To Json    ${resp.content}
    ${backupfile_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${backupfile_id}

Create Test Model
    [Documentation]    Create model we can use to test restore
    [Tags]    test2
    ${name}=    Generate Random Value    string
    ${data}=    Create Dictionary    name=${name}    flavor=one    description=for_backup_testing
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/flavors    ${data}
    ${json_content}=    To Json    ${resp.content}
    ${testmodel_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${testmodel_id}

Perform Backup
    [Documentation]    Perform backup
    [Tags]    test3
    ${data}=    Create Dictionary    operation=create    file_id=${backupfile_id}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupoperations    ${data}
    ${json_content}=    To Json    ${resp.content}
    ${backupop_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${backupop_id}
    Wait Until Keyword Succeeds    ${timeout}    5s    Ensure Backup Created

Modify Test Model
    [Documentation]    Modify the test model
    [Tags]    test4
    ${data}=    Create Dictionary    flavor=two
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Put    /xosapi/v1/core/flavors    ${data}   ${testmodel_id}
    ${json_content}=    To Json    ${resp.content}

Perform Restore
    [Documentation]    Perform Restore
    [Tags]    test5
    ${data}=    Create Dictionary    operation=restore    file_id=${backupfile_id}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupoperations    ${data}
    ${json_content}=    To Json    ${resp.content}
    ${backupop_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${backupop_id}
    Wait Until Keyword Succeeds    ${timeout}    5s    Ensure Restore Failed

Verify Test Model Still Updated
    [Documentation]    Verify Test Model has updated contents
    [Tags]    test6
    ${resp}=    Cord Get   /xosapi/v1/core/flavors/${testmodel_id}
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings   ${jsondata['flavor']}    two

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json    allow_modify_feedback=True
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}

Teardown
    [Documentation]    Delete all https sessions
#    Run Keyword If    ${cleanup} == ${true}    Ensure Service Deleted
#    Run Keyword If    ${cleanup} == ${true}    Ensure Service Unloaded
    Delete All Sessions

Ensure Backup Created
    [Documentation]    Wait for a backupoperation to be in "created" state
    Wait Until Keyword Succeeds    200s    2s    CORD Get    /xosapi/v1/core/users
    ${resp}=   Get Request    ${SERVER_IP}    uri=/xosapi/v1/core/backupoperations/${backupop_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings     ${jsondata['status']}    created

Ensure Restore Failed
    [Documentation]    Wait for a backupoperation to be in "created" state
    Wait Until Keyword Succeeds    200s    2s    CORD Get    /xosapi/v1/core/users
    ${resp}=   Get Request    ${SERVER_IP}    uri=/xosapi/v1/core/backupoperations/${backupop_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings     ${jsondata['status']}    failed
