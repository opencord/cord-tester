# XOS Backup Tests
#

*** Settings ***
Documentation     Test backup/restore of a models in XOS
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
Test Template     Validate Operation

*** Variables ***
${timeout}            300s
${fail_try}           fail_try_models_
${fail_restore}       fail_before_restore_
${fail_backup}        fail_before_backup_
${flavor_original}    one
${flavor_updated}     two

*** Test Cases ***
Backup    ${EMPTY}    created    restored    ${flavor_original}

Backup Fail Try    ${fail_try}    created    failed    ${flavor_updated}

Backup Fail Before Restore    ${fail_restore}    created    failed    ${flavor_updated}

Backup Fail Before Backup    ${fail_backup}    failed

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json    allow_modify_feedback=True
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}

Teardown
    [Documentation]    Delete all https sessions
    Delete All Sessions

Validate Operation
    [Documentation]    Tests and validates various backup/restore operations
    [Arguments]    ${scenario}    ${backup_state}    ${restore_state}=${EMPTY}    ${flavor_expected}=${EMPTY}
    ${backup_id}=    Create BackupFile    ${scenario}
    ${test_model_id}=    Create Test Model
    ${backup_operation_id}=    Perform Backup    ${backup_id}    ${backup_state}
    Run Keyword If    '${restore_state}' != '${EMPTY}'    Modify Test Model    ${test_model_id}
    Run Keyword If    '${restore_state}' != '${EMPTY}'    Perform Restore    ${backup_id}    ${restore_state}
    Run Keyword If    '${restore_state}' != '${EMPTY}'    Verify Test Model    ${test_model_id}    ${flavor_expected}

Create BackupFile
    [Documentation]    Create a backupfile model
    [Arguments]    ${operation}
    ${file_name}=    Generate Random Value    string
    ${file_uri}=     Catenate    SEPARATOR=    file:///var/run/xos/backup/local/    ${operation}    ${file_name}
    ${data}=    Create Dictionary    name=${file_name}    uri=${file_uri}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupfiles    ${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${json_content}=    To Json    ${resp.content}
    ${id}=    Get From Dictionary    ${json_content}    id
    [Return]    ${id}

Create Test Model
    [Documentation]    Create model we can use to test restore
    ${name}=    Generate Random Value    string
    ${data}=    Create Dictionary    name=${name}    flavor=${flavor_original}    description=for_backup_testing
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/flavors    ${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${json_content}=    To Json    ${resp.content}
    ${id}=    Get From Dictionary    ${json_content}    id
    [Return]    ${id}

Perform Backup
    [Documentation]    Perform backup
    [Arguments]    ${backupfile_id}    ${status}
    ${data}=    Create Dictionary    operation=create    file_id=${backupfile_id}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupoperations    ${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${json_content}=    To Json    ${resp.content}
    ${id}=    Get From Dictionary    ${json_content}    id
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Backup    ${id}    ${status}

Modify Test Model
    [Documentation]    Modify the test model
    [Arguments]    ${testmodel_id}
    ${data}=    Create Dictionary    flavor=${flavor_updated}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Put    /xosapi/v1/core/flavors    ${data}   ${testmodel_id}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings   ${jsondata['flavor']}    two

Perform Restore
    [Documentation]    Perform Restore
    [Arguments]    ${id}    ${restore_state}
    ${data}=    Create Dictionary    operation=restore    file_id=${id}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/core/backupoperations    ${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${json_content}=    To Json    ${resp.content}
    ${backupop_id}=    Get From Dictionary    ${json_content}    id
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Restore    ${backupop_id}    ${restore_state}

Verify Test Model
    [Documentation]    Verify Test Model has original contents
    [Arguments]    ${testmodel_id}    ${value}
    ${resp}=    Cord Get   /xosapi/v1/core/flavors/${testmodel_id}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings   ${jsondata['flavor']}    ${value}

Validate Backup
    [Documentation]    Wait for a backupoperation to be in "created" state
    [Arguments]    ${id}    ${state}
    ${resp}=   Get Request    ${SERVER_IP}    uri=/xosapi/v1/core/backupoperations/${id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings     ${jsondata['status']}    ${state}

Validate Restore
    [Documentation]    Validate Backup operation status
    [Arguments]    ${id}    ${state}
    ${resp}=   Get Request    ${SERVER_IP}    uri=/xosapi/v1/core/backupoperations/${id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${jsondata}=    To Json    ${resp.content}
    Should Be Equal As Strings     ${jsondata['status']}    ${state}