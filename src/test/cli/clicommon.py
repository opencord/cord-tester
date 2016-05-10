import os,sys
from utilities import Utilities, utilities
from scapy.all import *

#log.setLevel('INFO')
class MAIN(object):
    def __init__(self):
        global utilities
        self.log = log
        self.logdir = os.getenv('HOME')
        self.logHeader = ''
        self.utilities = utilities
        self.TRUE = True
        self.FALSE = False
        self.EXPERIMENTAL_MODE = self.FALSE

    def cleanup(self): pass

    def exit(self): pass

main = MAIN()
