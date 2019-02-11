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
    ${output}=    Run    kubectl get pods | grep demo-simpleexampleservice | grep -i terminating | wc -l
    Should Be Equal As Integers    ${output}    0
    ${output}=    Run    kubectl get jobs | grep demo-simpleexampleservice-tosca-loader | grep "1 .*1 " | wc -l
    Should Be Equal As Integers    ${output}    1
    ${resp} =   CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices
    ${jsondata} =    To Json    ${resp.content}
    ${length} =    Get Length    ${jsondata['items']}
    Should Be Equal As Integers    ${length}    1
    #Wait Until Keyword Succeeds    200s    2s    CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleservices




