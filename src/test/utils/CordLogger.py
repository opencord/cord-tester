from OnosLog import OnosLog
from scapy.all import log
import unittest

class CordLogger(unittest.TestCase):

    def setUp(self):
        '''Read the log buffer'''
        try:
            onosLog = OnosLog()
            st, output = onosLog.get_log()
            onosLog.close()
        except: pass

    def tearDown(self):
        '''Dump the log buffer for ERRORS/warnings'''
        try:
            onosLog = OnosLog()
            st, output = onosLog.get_log( ('ERROR','WARN') )
            onosLog.close()
            if st and output:
                log.info('\nTest %s has errors and warnings\n' %self._testMethodName)
                log.info('%s' %output)
            else:
                log.info('\nTest %s has no errors and warnings in the logs' %self._testMethodName)
        except: pass
