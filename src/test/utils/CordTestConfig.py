import inspect
import unittest
import json
import os
from nose.tools import assert_not_equal
from nose.plugins import Plugin
from CordTestUtils import log_test as log
from CordTestUtils import running_on_pod
from VolthaCtrl import voltha_setup, voltha_teardown
from SSHTestAgent import SSHTestAgent
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
    def stopContext(self, context):
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

def get_test_class(module):
    class_test = None
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, unittest.TestCase):
            if obj.__name__.endswith('exchange'):
                class_test = obj
                break
            else:
                class_test = obj

    return class_test

def setup_module(module):
    class_test = get_test_class(module)
    assert_not_equal(class_test, None)
    module_name = module.__name__.split('.')[-1]
    cfg = '{}.json'.format(module_name)
    module_config = os.path.join(os.path.dirname(module.__file__), cfg)
    if os.access(module_config, os.F_OK):
        with open(module_config) as f:
            json_data = json.load(f)
            for k, v in json_data.iteritems():
                setattr(class_test, k, v)

    #check for voltha and configure as appropriate
    voltha_attrs = dict(host='172.17.0.1',
                        rest_port = 8881,
                        config_fake = False,
                        olt_type = 'ponsim',
                        olt_mac = '00:0c:e2:31:12:00',
                        uplink_vlan_map = { 'of:0000000000000001' : '222' }
                        )
    voltha_enabled = bool(int(os.getenv('VOLTHA_ENABLED', 0)))
    voltha_configure = True
    if hasattr(class_test, 'VOLTHA_AUTO_CONFIGURE'):
        voltha_configure = getattr(class_test, 'VOLTHA_AUTO_CONFIGURE')

    if voltha_enabled and voltha_configure:
        for k,v in voltha_attrs.iteritems():
            voltha_attr = 'VOLTHA_{}'.format(k.upper())
            if hasattr(class_test, voltha_attr):
                v = getattr(class_test, voltha_attr)
                voltha_attrs[k] = v
            else:
                setattr(class_test, voltha_attr, v)
        ret = voltha_setup(**voltha_attrs)
        if ret is not None:
            #setup the stage to drop voltha on the way out
            setattr(class_test, 'voltha_ctrl', ret[0])
            setattr(class_test, 'voltha_device', ret[1])
            setattr(class_test, 'voltha_switch_map', ret[2])

def teardown_module(module):
    class_test = get_test_class(module)
    if class_test is None:
        return
    if not hasattr(class_test, 'voltha_ctrl') or \
       not hasattr(class_test, 'voltha_device') or \
       not hasattr(class_test, 'voltha_switch_map'):
        return
    voltha_ctrl = getattr(class_test, 'voltha_ctrl')
    voltha_device = getattr(class_test, 'voltha_device')
    voltha_switch_map = getattr(class_test, 'voltha_switch_map')
    voltha_teardown(voltha_ctrl, voltha_device, voltha_switch_map)

def running_on_ciab():
    if running_on_pod() is False:
        return False
    head_node = os.getenv('HEAD_NODE', 'prod')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    agent = SSHTestAgent(host = HEAD_NODE, user = 'ubuntu', password = 'ubuntu')
    #see if user ubuntu works
    st, output = agent.run_cmd('sudo virsh list')
    if st is False and output is not None:
        #we are on real pod
        return False

    #try vagrant
    agent = SSHTestAgent(host = HEAD_NODE, user = 'vagrant', password = 'vagrant')
    st, output = agent.run_cmd('sudo virsh list')
    if st is True and output is not None:
        return True

    return False
