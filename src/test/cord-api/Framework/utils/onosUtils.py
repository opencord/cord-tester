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

import paramiko

def onos_command_execute(host, portNum, cmd, user='karaf', passwd='karaf'):
    """
    :param host: onos-cord or onos-fabric
    :param portNum: 8102 or 8101
    :param cmd: command to execute
    :param user: onos/karaf
    :param passwd: onos/karaf
    :return: output of command executed inside onos karaf (shell)
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=int(portNum), username=user, password=passwd)
        stdin, stdout, stderr = client.exec_command(cmd)
        while not stdout.channel.exit_status_ready():
            if stdout.channel.recv_ready():
                return stdout.read()
    finally:
        client.close()

def get_compute_node_ip(compute_node):
    """
    :param compute_node: one compute node information from output of 'cordvtn-nodes'
    :return: data_ip of that compute node
    """
    for line in compute_node.splitlines():
        columns = line.split()
        if len(columns) >= 2:
            return columns[2].split("/")[0]