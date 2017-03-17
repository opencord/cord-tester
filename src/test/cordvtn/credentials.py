import os

def get_credentials():
    n = {}
    n['username'] = os.environ['OS_USERNAME']
    n['password'] = os.environ['OS_PASSWORD']
    n['auth_url'] = os.environ['OS_AUTH_URL']
    n['tenant_name'] = os.environ['OS_TENANT_NAME']
    return n

def get_cinder_credentials():
    n = [os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'],
         os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL']]
    return n

def get_ceilo_credentials():
    n = {}
    n['os_username'] = os.environ['OS_USERNAME']
    n['os_password'] = os.environ['OS_PASSWORD']
    n['os_auth_url'] = os.environ['OS_AUTH_URL']
    n['os_tenant_name'] = os.environ['OS_TENANT_NAME']
    return n

def get_nova_credentials():
    n = {}
    n['username'] = os.environ['OS_USERNAME']
    n['api_key'] = os.environ['OS_PASSWORD']
    n['auth_url'] = os.environ['OS_AUTH_URL']
    n['project_id'] = os.environ['OS_TENANT_NAME']
    return n

def get_nova_credentials_v2():
    n = {}
    n['username'] = os.environ['OS_USERNAME']
    n['api_key'] = os.environ['OS_PASSWORD']
    n['auth_url'] = os.environ['OS_AUTH_URL']
    n['project_id'] = os.environ['OS_TENANT_NAME']
    return n

def get_nova_credentials_v3():
    n = {}
    n['version'] = '3'
    n['username'] = os.environ['OS_USERNAME']
    n['password'] = os.environ['OS_PASSWORD']
    n['project_id'] = os.environ['OS_TENANT_NAME']
    n['auth_url'] = os.environ['OS_AUTH_URL']
    return n

def get_nova_credentials_v11():
    n = {}
    n['version'] = '1.1'
    n['username'] = os.environ['OS_USERNAME']
    n['api_key'] = os.environ['OS_PASSWORD']
    n['auth_url'] = os.environ['OS_AUTH_URL']
    n['project_id'] = os.environ['OS_TENANT_NAME']
    return n
