// Copyright 2017-present Open Networking Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
node("intel-102") {
  timeout (120) {
    try {
      stage("Listing the VM") {
        timeout(1) {
          waitUntil {
            running_vms = sh returnStdout: true, script: """
            virsh list --all
            """
            echo "Running VMs: ${running_vms}"
            return true
          }
        }
        timeout(1) {
          waitUntil {
            running_vms = sh returnStdout: true, script: """
            virsh list --all | grep "c3po-mme1\\|c3po-hss1\\|ngic-cp1\\|ngic-dp1\\|c3po-dbn1" | grep -i running | wc -l
            """
            echo "Running VMs: ${running_vms}"
            return running_vms.toInteger() >= 5
          }
        }
      }
      stage("Connecting to ngic-cp1") {
//       ssh ngic-cp1 'sh test.sh'
        timeout(10) {
          waitUntil {
            ngic_cp1_output = sh returnStdout: true, script: """
            ssh ngic-cp1 'if pgrep -f [n]gic_controlplane; then pkill -f [n]gic_controlplane; fi'
            ssh ngic-cp1 'cd /home/ngic-rtc/cp && (./run.sh 2>/var/log/cicd_cp1.stderr 1>/var/log/cicd_cp1.stdout &)'
            sleep 1;
            ssh ngic-cp1 'pgrep -fl [n]gic_controlplane || (cat /var/log/cicd_cp1.stderr && cat /var/log/cicd_cp1.stdout && exit 1)'
            """
            echo "${ngic_cp1_output}"
            return true
          }
        }
        sh returnStdout: true, script: """
        ssh ngic-cp1 'pgrep -fl [n]gic_controlplane'
        """
      }
      stage("Connecting to ngic-dp1") {
        timeout(10) {
          waitUntil {
            ngic_dp1_output = sh returnStdout: true, script: """
            ssh ngic-dp1 'if pgrep -f [n]gic_dataplane; then pkill -f [n]gic_dataplane; fi'
            ssh ngic-dp1 'cd /home/ngic-rtc/dp && (./run.sh 2>/var/log/cicd_dp1.stderr 1>/var/log/cicd_dp1.stdout &)'
            sleep 10;
            ssh ngic-dp1 'cd /home/ngic-rtc/kni_ifcfg && ./kni-SGIdevcfg.sh'
            ssh ngic-dp1 'cd /home/ngic-rtc/kni_ifcfg && ./kni-S1Udevcfg.sh'
            ssh ngic-dp1 'pgrep -fl [n]gic_dataplane || (cat /var/log/cicd_dp1.stderr && cat /var/log/cicd_dp1.stdout && exit 1)'
            """
            echo "${ngic_dp1_output}"
            return true
          }
        }
        sh returnStdout: true, script: """
        ssh ngic-dp1 'pgrep -fl [n]gic_dataplane'
        """
      }
      stage("Connecting to c3po-hss1") {
        timeout(10) {
          waitUntil {
            c3po_hss1_output = sh returnStdout: true, script: """
            ssh c3po-hss1 'if pgrep -f [h]ss; then pkill -f [h]ss; fi'
            ssh c3po-hss1 'cd /home/c3po/hss && (./bin/hss -j conf/hss.json 2>/var/log/cicd_hss1.stderr 1>/var/log/cicd_hss1.stdout &)'
            sleep 2;
            ssh c3po-hss1 'pgrep -fl [h]ss || (cat /var/log/cicd_hss1.stderr && cat /var/log/cicd_hss1.stdout && exit 1)'
            """
            echo "${c3po_hss1_output}"
            return true
          }
        }
        sh returnStdout: true, script: """
        ssh c3po-hss1 'pgrep -fl [h]ss'
        """
      }
      stage("Connecting to c3po-mme1") {
        timeout(10) {
          waitUntil {
            c3po_mme1_output = sh returnStdout: true, script: """
            ssh c3po-mme1 'if pgrep -f [m]me-app; then pkill -f [m]me-app; fi'
            ssh c3po-mme1 'if pgrep -f [s]1ap-app; then pkill -f [s]1ap-app; fi'
            ssh c3po-mme1 'if pgrep -f [s]11-app; then pkill -f [s]11-app; fi'
            ssh c3po-mme1 'if pgrep -f [s]6a-app; then pkill -f [s]6a-app; fi'
            sleep 1;
            ssh c3po-mme1 'cd /home/openmme/src/mme-app && export LD_LIBRARY_PATH=../common/ && (./mme-app 2>/var/log/cicd_mme_mme_app.stderr 1>/var/log/cicd_mme_mme_app.stdout &)'
            ssh c3po-mme1 'cd /home/openmme/src/s1ap && export LD_LIBRARY_PATH=../common/ && (./s1ap-app 2>/var/log/cicd_mme_s1ap_app.stderr 1>/var/log/cicd_mme_s1ap_app.stdout &)'
            ssh c3po-mme1 'cd /home/openmme/src/s11 && export LD_LIBRARY_PATH=../common/ && (./s11-app 2>/var/log/cicd_mme_s11_app.stderr 1>/var/log/cicd_mme_s11_app.stdout &)'
            ssh c3po-mme1 'cd /home/openmme/src/s6a && export LD_LIBRARY_PATH=../common/ && (./s6a-app 2>/var/log/cicd_mme_s6a_app.stderr 1>/var/log/cicd_mme_s6a_app.stdout &)'
            sleep 2;
            ssh c3po-mme1 'pgrep -fl [m]me-app || (cat /var/log/cicd_mme_mme_app.stderr && cat /var/log/cicd_mme_mme_app.stdout && exit 1)'
            ssh c3po-mme1 'pgrep -fl [s]1ap-app || (cat /var/log/cicd_mme_s1ap_app.stderr && cat /var/log/cicd_mme_s1ap_app.stdout && exit 1)'
            ssh c3po-mme1 'pgrep -fl [s]11-app || (cat /var/log/cicd_mme_s11_app.stderr && cat /var/log/cicd_mme_s11_app.stdout && exit 1)'
            ssh c3po-mme1 'pgrep -fl [s]6a-app || (cat /var/log/cicd_mme_s6a_app.stderr && cat /var/log/cicd_mme_s6a_app.stdout && exit 1)'
            """
            echo "${c3po_mme1_output}"
            return true
          }
          sh returnStdout: true, script: """
          ssh c3po-mme1 'pgrep -f [m]me-app && pgrep -f [s]1ap-app && pgrep -f [s]11-app && pgrep -fl [s]6a-app '
          """
        }
      }
      stage("Connecting to Polaris") {
        timeout(10) {
          waitUntil {
            test_output = sh returnStdout: true, script: """
            ssh polaris 'cd /root/LTELoadTester && nettest -emulator 127.0.0.1:5678:enb,127.0.0.1:6789:ipte Attach-Detach-wdata.tcl > test-output.log'
            ssh polaris 'cd /root/LTELoadTester && cat test-output.log'
            """
            echo "Polaris log: ${test_output}"
            return true
          }
        }
        sh returnStdout: true, script: """
        ssh polaris 'cd /root/LTELoadTester && grep -P -o "Test pass percentage.*?100%" test-output.log'
        """
      }
      /*
      stage("Kill apps") {
        sh returnStdout: true, script: """
        ssh ngic-cp1 'if pgrep -f [n]gic_controlplane; then pkill -f [n]gic_controlplane; fi'
        ssh ngic-dp1 'if pgrep -f [n]gic_dataplane; then pkill -f [n]gic_dataplane; fi'
        ssh c3po-hss1 'if pgrep -f [h]ss; then pkill -f [h]ss; fi'
        ssh c3po-mme1 'if pgrep -f [m]me-app; then pkill -f [m]me-app; fi'
        ssh c3po-mme1 'if pgrep -f [s]1ap-app; then pkill -f [s]1ap-app; fi'
        ssh c3po-mme1 'if pgrep -f [s]11-app; then pkill -f [s]11-app; fi'
        ssh c3po-mme1 'if pgrep -f [s]6a-app; then pkill -f [s]6a-app; fi'
        """
      }
      */
      currentBuild.result = 'SUCCESS'
    } catch (err) {
      currentBuild.result = 'FAILURE'
    }
    echo "RESULT: ${currentBuild.result}"
  }
}
