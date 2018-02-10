# CORD Test Environment

Several jenkins based jobs are created to run tests on the following platforms
* Physical POD
* Virtual POD(Cord-in-a-Box)
* VMs

## Test Beds
Following picture below describes various test environments that are used to setup CORD and a brief overview on the type of tests that are performed on that test bed.

![Test Beds](images/qa-testbeds.png)

## Jenkins Test Setup

The following diagram shows how the test servers are interconnected

![QA Jenkins Setup](images/qa-jenkins.png)

* To view results from recent runs of the jenkins jobs, please view the [Jenkins dashboard](https://jenkins.opencord.org/)

## Jenkins Integration with Physical POD

The following diagram shows how Jenkins interconnects with a Physical POD.

![QA Physical POD setup](images/qa-pod-setup.png)
