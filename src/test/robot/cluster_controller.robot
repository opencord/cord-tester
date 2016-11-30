*** Settings ***
Documentation  Run Cord verification test cases for Cluster
Resource  cord_resource.robot
Suite Setup  Cord Cluster Setup
Suite Teardown  Cord Teardown

*** Variables ***
${NODES}          3
${EXTRA_OPTS}     -v

*** Test Cases ***
Verify Onos Controllers Restart Functionality
  [Documentation]  Verify ONOS cluster by restarting controllers iteratively
  ${rc}=  Run Cord Tester  cluster:cluster_exchange.test_cluster_controller_restarts
  Should Be Equal As Integers  ${rc}  0

Verify Onos Single Controller Restart Functionality
  [Documentation]  Verify ONOS cluster by restarting the same controller
  ${rc}=  Run Cord Tester  cluster:cluster_exchange.test_cluster_single_controller_restarts
  Should Be Equal As Integers  ${rc}  0

*** Keywords ***
Cord Cluster Setup
  [Documentation]  Configure a ${NODES} node ONOS cluster for cord tester
  ${output}  Run  sudo docker ps |grep cord-onos | tr -s ' ' | awk '{print $NF}' | xargs docker kill
  Cord Setup
