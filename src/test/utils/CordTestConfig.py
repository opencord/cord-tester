import inspect
import unittest
import json
import os
from nose.tools import assert_not_equal
from nose.plugins import Plugin
from CordTestUtils import log_test as log

log.setLevel('INFO')

class CordTestConfigRestore(Plugin):
    name = 'cordTestConfigRestore'
    context = None
    restore_methods = ('configRestore', 'config_restore',)

    def options(self, parser, env=os.environ):
        super(CordTestConfigRestore, self).options(parser, env = env)

    def configure(self, options, conf):
        self.enabled = True

    #just save the test case context on start
    def startContext(self, context):
        if inspect.isclass(context) and issubclass(context, unittest.TestCase):
            if context.__name__.endswith('exchange'):
                self.context = context

    #reset the context on exit
    def afterContext(self, context):
        if inspect.isclass(context) and issubclass(context, unittest.TestCase):
            if context.__name__.endswith('exchange'):
                self.context = None

    def doFailure(self, test, exception):
        if self.context:
            log.info('Inside test case failure for test: %s' %self.context.__name__)
            for restore_method in self.restore_methods:
                if hasattr(self.context, restore_method):
                    method = getattr(self.context, restore_method)
                    #check only for class/static methods
                    if method.__self__ is self.context:
                        method()
                        break

    def addError(self, test, exception):
        self.doFailure(test, exception)

    def addFailure(self, test, exception):
        self.doFailure(test, exception)

def setup_module(module):
    class_test = None
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, unittest.TestCase):
            if obj.__name__.endswith('exchange'):
                class_test = obj
                break
            else:
                class_test = obj

    assert_not_equal(class_test, None)
    module_name = module.__name__.split('.')[-1]
    cfg = '{}.json'.format(module_name)
    module_config = os.path.join(os.path.dirname(module.__file__), cfg)
    if os.access(module_config, os.F_OK):
        with open(module_config) as f:
            json_data = json.load(f)
            for k, v in json_data.iteritems():
                setattr(class_test, k, v)
