
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import subprocess
import requests
import json
import time
from CordTestUtils import log_test as log, getstatusoutput, get_controller
from OnosCtrl import OnosCtrl

class perf(object):
    def  __init__(self, controller, interface = 'eth0'):
         self.controller = controller
         self.interface = interface

    def  know_cpu_freq(self):
         freq = open('/proc/cpuinfo/','r')
         freqs = freq.read()
         freq.seek(0)
         cpuentry = freq.readline()
         cpusplit = cpuentry.split()

         while cpusplit[0] != "cpu":
              while cpusplit[0] != "MHz":
                    cpuline = freq.readline()
                    cpusplit = cpuline.split()
         freq.close()
         cpu_mhz = cpusplit[3]
         return cpu_mhz

    def  retrieve_cpu_stats(self):
         cpu = open('/proc/stat/','r').readlines()[0]
         return map(float, cpu.split()[1:5])

    def  validate_cpu_performance(self, interval):
         time_stamp1 = retrieve_cpu_stats()
         time.sleep(interval)
         time_stamp2 = retrieve_cpu_stats()
         diff = [time_stamp2[i] - time_stamp1[i] for i in range(len(time_stamp1))]
         try:
             return 1.0 - (diff[-1:].pop()/(sum(diff)*1.0))
         except:
             return 0.0

    def  memory_usage(self):
         cmd_run = subprocess.check_output(['free','-b'])
         memory = cmd_run.split()
         total = int(memory[7])
         used = int(memory[8])
         free = int(memory[9])
         return total, used, free

    def  rx_network_stats(self, intf):
         for entry in open('/proc/net/dev', 'r'):
             if intf in entry:
                stat = entry.split('%s:' % intf)[1].split()
                rx_bytes = stat[0]
                rx_packets = stat[1]
                rx_errors = stat[2]
                rx_drops = stat[3]
         return int(rx_bytes), int(rx_packets), int(rx_errors), int(rx_drops)

    def  tx_network_stats(self, intf):
         for entry in open('/proc/net/dev', 'r'):
             if intf in entry:
                stat = entry.split('%s:' % intf)[1].split()
                tx_bytes = stat[8]
                tx_packets = stat[9]
                tx_errors = stat[10]
                tx_drops = stat[11]
         return int(tx_bytes), int(tx_packets), int(tx_errors), int(tx_drops)

    def  check_node_uptime(self):
         return float(open('/proc/uptime','r').read().split(' ')[0])

