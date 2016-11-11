import os
import re
from SSHTestAgent import SSHTestAgent

class OnosLog(object):
    CLI_USER = 'karaf'
    CLI_PASSWD = 'karaf'
    CLI_PORT = 8101
    HOST = os.getenv('ONOS_CONTROLLER_IP', '172.17.0.2')
    last_snapshot_map = {}

    def __init__(self, host = HOST):
        self.ssh_agent = SSHTestAgent(host = host, user = self.CLI_USER,
                                      password = self.CLI_PASSWD, port = self.CLI_PORT)
        if not OnosLog.last_snapshot_map.has_key(host):
            OnosLog.last_snapshot_map[host] = []

    @classmethod
    def get_last_snapshot(cls, host):
        if cls.last_snapshot_map.has_key(host):
            return cls.last_snapshot_map[host]
        return []

    @classmethod
    def update_last_snapshot(cls, host, res):
        cls.last_snapshot_map[host] = res

    def get_log(self, search_terms = None, exception = True):
        """Run the command on the test host"""
        cmd = 'cat /root/onos/apache-karaf-3.0.5/data/log/karaf.log'
        st, output = self.ssh_agent.run_cmd(cmd)
        if st is False:
            return output
        exception_map = {'Exception' : [] }
        last_snapshot = self.get_last_snapshot(self.ssh_agent.host)
        lines = output.splitlines()
        if search_terms:
            if type(search_terms) is str:
                terms = [ search_terms ]
            else:
                terms = list(search_terms)
            if exception is True and 'Exception' not in terms:
                terms.append('Exception')
            match_lines = []
            last_len = len(last_snapshot)
            for i in xrange(0, len(lines)):
                if i < last_len and lines[i] in last_snapshot:
                    ##skip lines matching the last snapshot
                    continue
                for t in terms:
                    if lines[i].find(t) >= 0:
                        match_lines.append(lines[i])
                        if t == 'Exception':
                            exception_map[t] = lines[i+1:i+1+10]
            output = '\n'.join(match_lines)
            output += '\n'.join(exception_map['Exception'])

        #update the last snapshot
        self.update_last_snapshot(self.ssh_agent.host, lines)
        return st, output

    def search_log_pattern(self, pattern):
        r_pat = re.compile(pattern)
        cmd = 'cat /root/onos/apache-karaf-3.0.5/data/log/karaf.log'
        st, output = self.ssh_agent.run_cmd(cmd)
        if st is False:
            return None
        return r_pat.findall(output)

if __name__ == '__main__':
    onos = os.getenv('ONOS_CONTROLLER_IP', '172.17.0.2')
    onos_log = OnosLog(host = onos)
    print('Checking for INFO')
    st, output = onos_log.get_log('INFO')
    print(st, output)
    print('\n\nChecking for ERROR\n\n')
    st, output = onos_log.get_log('ERROR')
    print(st, output)
    print('Checking for ERROR and INFO')
    st, output = onos_log.get_log(('ERROR', 'INFO'))
    print(st, output)
    pat = onos_log.search_log_pattern('ApplicationManager .* Started')
    if pat:
        print(pat)
    else:
        print('Onos did not start')
