import inspect
import unittest
import json
import os
from nose.tools import assert_not_equal

def setup_module(module):
    class_found = None
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, unittest.TestCase):
            if obj.__name__.endswith('exchange'):
                class_found = obj
                break
            else:
                class_found = obj

    assert_not_equal(class_found, None)
    try:
        module_name = module.__name__.split('.')[-1]
    except:
        module_name = module.__name__

    cfg = '{}.json'.format(module_name)
    module_config = os.path.join(os.path.dirname(module.__file__), cfg)
    if os.access(module_config, os.F_OK):
        with open(module_config) as f:
            json_data = json.load(f)
            for k, v in json_data.iteritems():
                setattr(class_found, k, v)
