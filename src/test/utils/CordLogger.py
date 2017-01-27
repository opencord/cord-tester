from OnosLog import OnosLog
from scapy.all import log
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl, get_mac
from docker import Client
from CordContainer import *
import json
import requests
import unittest
import os
import time

def get_controller_names(controllers):
        controller_names = [ 'cord-onos' if controllers.index(c) == 0 else 'cord-onos-{}'.format(controllers.index(c)+1) for c in controllers ]
        return controller_names

def get_controller_map(controllers):
        controller_map = ( ('cord-onos' if controllers.index(c) == 0 else 'cord-onos-{}'.format(controllers.index(c)+1),c) for c in controllers )
        return dict(controller_map)

class CordLogger(unittest.TestCase):

    controllers = os.getenv('ONOS_CONTROLLER_IP', '').split(',')
    controller_names = get_controller_names(controllers)
    controller_map = get_controller_map(controllers)
    cliSessions = {}
    onosLogLevel = 'INFO'
    curLogLevel = onosLogLevel
    testLogLevel = os.getenv('LOG_LEVEL', onosLogLevel)
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup')
    archive_dir = os.path.join(setup_dir, 'test_logs')
    onos_data_dir = os.path.join(setup_dir, 'cord-onos-data')

    @classmethod
    def cliSessionEnter(cls):
        try:
            for controller in cls.controllers:
                if not controller:
                    continue
                retries = 0
                while retries < 30:
                    cli = OnosCliDriver(controller = controller, connect = True)
                    if cli.handle:
                        cls.cliSessions[controller] = cli
                        break
                    else:
                        retries += 1
                        time.sleep(2)
        except:
            pass

    @classmethod
    def cliSessionExit(cls):
        try:
            for controller, cli in cls.cliSessions.items():
                if cli:
                    cli.disconnect()
        except:
            pass

    def setUp(self):
        '''Read the log buffer'''
        self.logSet()
        try:
            onosLog = OnosLog()
            st, output = onosLog.get_log()
        except: pass

    def tearDown(self):
        '''Dump the log buffer for ERRORS/warnings'''
        #reset the log level back to default log level after a test
        self.logSet(level = self.onosLogLevel)
        try:
            onosLog = OnosLog()
            st, output = onosLog.get_log( ('ERROR','WARN') )
            if st and output:
                log.info('\nTest %s has errors and warnings\n' %self._testMethodName)
                log.info('%s' %output)
            else:
                log.info('\nTest %s has no errors and warnings in the logs' %self._testMethodName)
        except: pass
        try:
            self.archive_results(self._testMethodName)
        except: pass

    @classmethod
    def archive_results(cls, testName, controllers = None, iteration = None):
        if not os.path.exists(cls.onos_data_dir):
            return cls.archive_results_unshared(testName, controllers = controllers, iteration = iteration)
        if not os.path.exists(cls.archive_dir):
            os.mkdir(cls.archive_dir)
        if controllers is None:
            controllers = cls.controllers
            controller_map = cls.controller_map
        else:
            controller_map = get_controller_map(controllers)

        iteration_str = '' if iteration is None else '_{}'.format(iteration)
        for c in controller_map.keys():
            archive_file = os.path.join(cls.archive_dir,
                                        'logs_{}_{}{}.tar.gz'.format(controller_map[c], testName, iteration_str))
            archive_path = os.path.join(cls.setup_dir, '{}-data'.format(c), 'log')
            cmd = 'cd {} && tar cvzf {} .'.format(archive_path, archive_file)
            try:
                os.system(cmd)
            except: pass

    @classmethod
    def archive_results_unshared(cls, testName, controllers = None, iteration = None, cache_result = False):
        log_map = {}
        if controllers is None:
            controllers = cls.controllers
        else:
            if type(controllers) in [ str, unicode ]:
                controllers = [ controllers ]
        try:
            for controller in controllers:
                onosLog = OnosLog(host = controller)
                st, output = onosLog.get_log(cache_result = cache_result)
                log_map[controller] = (st, output)
        except:
            return

        if not os.path.exists(cls.archive_dir):
            os.mkdir(cls.archive_dir)
        for controller, results in log_map.items():
            st, output = results
            if st and output:
                iteration_str = '' if iteration is None else '_{}'.format(iteration)
                archive_file = os.path.join(cls.archive_dir,
                                            'logs_{}_{}{}'.format(controller, testName, iteration_str))
                archive_cmd = 'gzip -9 -f {}'.format(archive_file)
                if os.access(archive_file, os.F_OK):
                    os.unlink(archive_file)
                with open(archive_file, 'w') as fd:
                    fd.write(output)
                try:
                    os.system(archive_cmd)
                except: pass

    @classmethod
    def logSet(cls, level = None, app = 'org.onosproject', controllers = None, forced = False):
        #explicit override of level is allowed to reset log levels
        if level is None:
            level = cls.testLogLevel
        #if we are already at current/ONOS log level, there is nothing to do
        if forced is False and level == cls.curLogLevel:
            return
        if controllers is None:
            controllers = cls.controllers
        else:
            if type(controllers) in [str, unicode]:
                controllers = [ controllers ]
        cls.cliSessionEnter()
        try:
            for controller in controllers:
                if cls.cliSessions.has_key(controller):
                    cls.cliSessions[controller].logSet(level = level, app = app)
            cls.curLogLevel = level
        except:
            pass
        cls.cliSessionExit()

    @classmethod
    def stat_option(cls, stat = None, serverDetails = None):
        # each stat option we can do some specific functions
        if stat is None:
           stat = cls.statOptionsList
        if serverDetails is None:
           serverDetails = cls.serverOptionsList
        stat_choice = 'COLLECTD'
        test_name = cls.testHostName
        test_image = 'cord-test/nose'
        if stat_choice in stat:
           onos_ctrl = OnosCtrl('org.onosproject.cpman')
           status, _ = onos_ctrl.activate()
           if serverDetails is '':
              ## default Test Container is used to install CollectD
              pass
           elif serverDetails in 'NEW':
                test_image = 'cord-test/exserver'
                test_name ='cord-collectd'
           else:
               pass
               # cls.connect_server(serverDetails)
               ## TO-DO for already up and running server, install collectd agent etc...
           cls.start_collectd_agent_in_server(name = test_name, image = test_image)
           for controller in cls.controllers:
               if not controller:
                  continue
               url_mem_stats =  'http://%s:8181/onos/cpman/controlmetrics/memory_metrics'%(controller)
               url_cpu_stats =  'http://%s:8181/onos/cpman/controlmetrics/cpu_metrics'%(controller)
               auth = ('karaf', 'karaf')
               cls.collectd_agent_metrics(controller, auth, url = url_cpu_stats)
               cls.collectd_agent_metrics(controller, auth, url = url_mem_stats)
        return


    @classmethod
    def collectd_agent_metrics(cls,controller=None, auth =None, url = None):
        '''This function is getting rules from ONOS with json format'''
        if url:
           resp = requests.get(url, auth = auth)
           log.info('Collectd agent has provided metrics via ONOS controller, url = %s \nand status = %s' %(url,resp.json()))
        return resp


    @classmethod
    def start_collectd_agent_in_server(cls, name = None, image = None):
        container_cmd_exec = Container(name = name, image = image)
        tty = False
        dckr = Client()
        cmd =  'sudo /etc/init.d/collectd start'
        i = container_cmd_exec.execute(cmd = cmd, tty= tty, stream = True)
        return

    @classmethod
    def disable_onos_apps(cls, stat = None, app = None):
        stat_choice = 'COLLECTD'
        if stat is None:
           stat = cls.statOptionsList
        if stat_choice in stat:
            onos_ctrl = OnosCtrl('org.onosproject.cpman')
            status, _ = onos_ctrl.deactivate()

