*** Settings ***
Documentation     Library to retrieve status fields from ATT WorkFlow Driver Service Instance List 
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           ../Framework/utils/utils.py
Library           ../Framework/restApi.py

*** Keywords ***
Service Instance Status Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns Status and authentication_state field values from att work flow driver for a particular ONU device
    ${json_result}=    restApi.ApiGet    ATT_SERVICEINSTANCES
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${onu_device}
    ${status}=  Get From Dictionary    ${getJsonDict}   valid 
    ${authentication_status}=  Get From Dictionary    ${getJsonDict}   authentication_state
    [Return]    ${status}    ${authentication_status} 
