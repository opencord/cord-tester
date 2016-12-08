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

    @classmethod
    def cliSessionEnter(cls):
        try:
            for controller in cls.controllers:
                if not controller:
                    continue
                retries = 0
                while retries < 3:
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
