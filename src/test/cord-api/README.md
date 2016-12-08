## CORD API TESTS

This module contains tests using XOS APIs.
Testcases are written in RobotFramework utilizing some automated python library framework.  

## Prerequisites:
 
  * Robot Framework

## Install Robot Framework:
```bash
     $ sudo pip install robotframework
     $ sudo pip install pygments
     $ sudo apt-get install python-wxgtk2.8
     $ sudo pip install robotframework-ride
```
   - To bring up IDE for the robot framework
```bash
   $ ride.py
```
## Execute testcases:
   * Testcases can be run using ride.py IDE
   * Or From the command line
```bash
     $ cd cord-tester/src/test/cord-api/Tests
     $ pybot <testcase.txt>
```
## Input Files for the testcases
* Input files for the testcases are present in the "Tests/data" directory, a set of input files to run the testcases
