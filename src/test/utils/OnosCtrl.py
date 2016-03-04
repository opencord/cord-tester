import json
import requests
import os,sys,time

class OnosCtrl:
    
    def __init__(self, app, controller = None):
        self.app = app
        if controller is None:
            self.controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
        else:
            self.controller = controller
        self.app_url = 'http://%s:8181/onos/v1/applications/%s' %(self.controller, self.app)
        self.cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(self.controller)
        self.auth = ('karaf', 'karaf')

    def config(self, config):
        if config:
            json_data = json.dumps(config)
            resp = requests.post(self.cfg_url, auth = self.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    def activate(self):
        resp = requests.post(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    def deactivate(self):
        resp = requests.delete(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code


