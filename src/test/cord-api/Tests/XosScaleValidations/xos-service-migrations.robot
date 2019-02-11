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
${repository}    smbaker/simpleexampleservice-synchronizer
${migration1}    migration1
${migration2}    migration2
${helm_chart}    ~/cord/helm-charts/xos-profiles/demo-simpleexampleservice
*** Test Cases ***
Cleanup If Necessary
    [Tags]    test0
    [Documentation]    Cleanup from previous run. Not necessary during automation as there will be no previous run.
    Ensure Service Deleted
    Ensure Service Unloaded
Ensure Clean Environment
    [Documentation]    Ensure the service is not installed and its endpoint is not being served
    [Tags]    test1
    ${output}=    Run    helm ls | grep demo-simpleexampleservice | wc -l
    Should Be Equal As Integers    ${output}    0
    ${resp} =    Get Request    ${SERVER_IP}    uri=/xosapi/v1/simpleexampleservice/simpleexampleservices
    Should Be Equal As Strings    ${resp.status_code}    404
Install initial version
    [Documentation]    Install version A of the service and wait for completion
    [Tags]    test2
    Run    helm install -n demo-simpleexampleservice --set simpleexampleservice.image.repository=${repository} --set simpleexampleservice.image.tag=${migration1} ${helm_chart}
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Service Running
Validate Service Version A
    [Documentation]    Validate fields from model in version A
    [Tags]    test3
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices
    ${jsondata} =    To Json    ${resp.content}
    ${length} =    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${dict}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${keys}=    Get Dictionary Keys    ${dict}
    : FOR    ${field}    IN    @{model_A_fields}
    \    List Should Contain Value    ${keys}    ${field}
    : FOR    ${field}    IN    @{model_B_only_fields}
    \    List Should Not Contain Value    ${keys}    ${field}
Upgrade Service
    [Documentation]    Upgrade the version of the service to version B and wait for completion
    [Tags]    test4
    ${rc}=    Run And Return RC    helm upgrade --set simpleexampleservice.image.repository=${repository} --set simpleexampleservice.image.tag=${migration2} --recreate-pods demo-simpleexampleservice ${helm_chart}
    Should Be Equal As Integers    ${rc}    0
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Service Running
Validate Service Version B
    [Documentation]    Validate fields from model in upgraded version B (2.0.0)
    [Tags]    test5
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices
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
    @{model_A_fields}=    Create List    service_message    service_secret
    @{model_B_fields}=    Create List    service_message    service_secret    new_field
    @{model_B_only_fields}=    Create List    new_field
    Set Suite Variable    @{model_A_fields}
    Set Suite Variable    @{model_B_fields}
    Set Suite Variable    @{model_B_only_fields}
Teardown
    [Documentation]    Delete all https sessions
    Delete All Sessions
Validate Service Running
    ${output}=    Run    helm ls | grep demo-simpleexampleservice | grep -i deployed | wc -l
    Should Be Equal As Integers    ${output}    1
    ${output}=    Run    kubectl get pods | grep demo-simpleexampleservice | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    1
    ${output}=    Run    kubectl get pods | grep demo-simpleexampleservice | grep -i terminating | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    0
    Wait Until Keyword Succeeds    200s    2s    CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices
Ensure Service Deleted
    ${output}=    Run    helm ls | grep demo-simpleexampleservice | grep -i deployed | wc -l
    Run Keyword If    ${output} == 1    Delete Service
Delete Service
    Log to Console    Deleating Service Helm Chart
    ${rc}=    Run And Return RC    helm del --purge demo-simplexampleservice
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
    \    Run Keyword If    "${dict['name']}" == "simpleexampleservice"    Run Keyword If    "${dict['state']}" == "load"    Unload Service
Unload Service
    [Documentation]    Unload the service
    Log To Console    Unloading Service
    ${data}=    Create Dictionary    name=simpleexampleservice    version=1.1.7
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    ${SERVER_IP}    uri=/xosapi/v1/dynamicload/unload_models    data=${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    Log To Console    Successfully Unloaded



