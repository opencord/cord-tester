from credentials import get_nova_credentials
from novaclient.client import Client

class novautils(object):

    def __init__(self, net_id, server_id):
        self.net_id = net_id#'ae0618cf-fa34-4e8b-816d-c1356c409119'
        self.server_id = server_id#'99889c8d-113f-4a7e-970c-77f1916bfe14'

    def get_nova_intance(self):
        creds = get_nova_credentials()
        nvclient= Client(**creds)
        return nvclient

    def create_instance_v2(self, vm_name):
        nvclient = self.get_nova_intance()
        image = nvclient.images.find(name="vsg-1.1")
        flavor = nvclient.flavors.find(name="m1.tiny")
        nic = [{'net-id': self.net_id}]
        instance = nvclient.servers.create(name=self.vm_name, image=image,
                                              flavor=flavor,
                                              nics=nic)
        time.sleep(5)
        return instance

    def get_flavors_list(self):
        nvclient = self.get_nova_intance()
        flavors_list = nvclient.flavors.list()
        return flavors_list

    def get_flavor_details(self):
        nvclient = self.get_nova_intance()
        flavors_list = nvclient.flavors.list()
        for fl in  flavors_list:
            return fl.name, fl.ram, fl.vcpus, fl.disk, fl.id

    def get_servers_list(self):
        nvclient = self.get_nova_intance()
        servers = nvclient.servers.list()
        return servers

    def get_server_details(self):
        nvclient = self.get_nova_intance()
        servers = nvclient.servers.get(self.server_id)
        for s in servers:
            return s.id, s.name, s.image, s.flavor, s.user_id

    def get_floating_ip_pools(self):
        nvclient = self.get_nova_intance()
        ip_list = nvclient.floating_ip_pools.list()
        return ip_list

    def get_host_list(self):
        nvclient = self.get_nova_intance()
        host_list = nvclient.hosts.list()
        return host_list

    def get_hypervisor_list(self):
        nvclient = self.get_nova_intance()
        hyper_list = nvclient.hypervisors.list()
        return hyper_list

    def get_images_list(self):
        nvclient = self.get_nova_intance()
        img_list = nvclient.images.list(detailed=True)
        return img_list

    def get_aggregates_list(self):
        nvclient = self.get_nova_intance()
        return nvclient.aggregates.list()



