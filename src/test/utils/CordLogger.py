from OnosLog import OnosLog
from scapy.all import log
from onosclidriver import OnosCliDriver
import unittest
import os
import time

class CordLogger(unittest.TestCase):

    controllers = os.getenv('ONOS_CONTROLLER_IP', '').split(',')
    cliSessions = {}
    onosLogLevel = 'INFO'
    curLogLevel = onosLogLevel
    testLogLevel = os.getenv('LOG_LEVEL', onosLogLevel)
    setup_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../setup')
    archive_dir = os.path.join(setup_dir, 'test_logs')

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
    def archive_results(cls, testName, controllers = None, iteration = None, cache_result = False):
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