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
${repository}    xosproject/simpleexampleservice-synchronizer
${migration1}    migration-test1
${migration2}    migration-test2
${helm_chart}    ~/cord/helm-charts/xos-services/simpleexampleservice
${cleanup}       ${true}

*** Test Cases ***
Ensure Clean Environment
    [Documentation]    Ensure the service is not installed and its endpoint is not being served
    [Tags]    test1
    ${output}=    Run    helm ls | grep simpleexampleservice | wc -l
    Should Be Equal As Integers    ${output}    0
    ${resp} =    Get Request    ${SERVER_IP}    uri=/xosapi/v1/simpleexampleservice/simpleexampleservices
    Should Be Equal As Strings    ${resp.status_code}    404

Install initial version
    [Documentation]    Install version A of the service and wait for completion
    [Tags]    test2
    Run    helm install -n simpleexampleservice --set image.repository=${repository} --set image.tag=${migration1} ${helm_chart}
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Service Running

Create Model
    [Documentation]    Create a service model
    [Tags]    test3
    ${model_name}=    Generate Random Value    string
    ${data}=    Create Dictionary    name=${model_name}    service_message=initial
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    CORD Post    /xosapi/v1/simpleexampleservice/simpleexampleservices    ${data}
    ${json_content}=    Evaluate    json.loads('''${resp.content}''')    json
    ${model_id}=    Get From Dictionary    ${json_content}    id
    Set Suite Variable    ${model_id}
    Set Suite Variable    ${model_name}

Validate Service Version A
    [Documentation]    Validate fields from model in version A
    [Tags]    test4
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices/${model_id}
    ${jsondata} =    To Json    ${resp.content}
    ${keys}=    Get Dictionary Keys    ${jsondata}
    : FOR    ${field}    IN    @{model_A_fields}
    \    List Should Contain Value    ${keys}    ${field}
    : FOR    ${field}    IN    @{model_B_only_fields}
    \    List Should Not Contain Value    ${keys}    ${field}
    Should Be Equal As Strings   ${jsondata['name']}    ${model_name}
    Should Be Equal As Strings   ${jsondata['service_message']}    initial

Upgrade Service
    [Documentation]    Upgrade the version of the service to version B and wait for completion
    [Tags]    test5
    ${rc}=    Run And Return RC    helm upgrade --set image.repository=${repository} --set image.tag=${migration2} --recreate-pods simpleexampleservice ${helm_chart}
    Should Be Equal As Integers    ${rc}    0
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Service Running

Validate Service Version B
    [Documentation]    Validate fields from model in upgraded version B (2.0.0)
    [Tags]    test6
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices/${model_id}
    ${jsondata} =    To Json    ${resp.content}
    ${keys}=    Get Dictionary Keys    ${jsondata}
    : FOR    ${field}    IN    @{model_B_fields}
    \    List Should Contain Value    ${keys}    ${field}
    Should Be Equal As Strings   ${jsondata['name']}    ${model_name}
    Should Be Equal As Strings   ${jsondata['service_message']}    initial
    Should Be Equal As Strings   ${jsondata['new_field']}    new_stuff

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
    Run Keyword If    ${cleanup} == ${true}    Ensure Service Deleted
    Run Keyword If    ${cleanup} == ${true}    Ensure Service Unloaded
    Delete All Sessions

Validate Service Running
    # wait for helm chart to be deployed
    ${output}=    Run    helm ls | grep simpleexampleservice | grep -i deployed | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for the synchronizer pod to be running
    ${output}=    Run    kubectl get pods | grep simpleexampleservice | grep -i running | grep 1/1 | wc -l
    Should Be Equal As Integers    ${output}    1
    # wait for no other synchronizer pods to be terminating
    ${output}=    Run    kubectl get pods | grep simpleexampleservice | grep -i terminating | wc -l
    Should Be Equal As Integers    ${output}    0
    # wait for the endpoint to exist
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices

Ensure Service Deleted
    ${output}=    Run    helm ls | grep simpleexampleservice | grep -i deployed | wc -l
    Run Keyword If    ${output} == 1    Delete Service

Delete Service
    Log    Deleating Service Helm Chart
    ${rc}=    Run And Return RC    helm del --purge simpleexampleservice
    Should Be Equal As Integers    ${rc}    0
    Log    Deleted Service Helm Chart

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
    Log    Unloading Service
    ${data}=    Create Dictionary    name=simpleexampleservice    version=1.1.7
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    ${SERVER_IP}    uri=/xosapi/v1/dynamicload/unload_models    data=${data}
    Should Be Equal As Strings    ${resp.status_code}    200
    Log    Successfully Unloaded
