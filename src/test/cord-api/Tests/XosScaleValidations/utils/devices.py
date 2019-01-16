from robot.api.deco import keyword

class OLTDeviceLibrary:

    @keyword('Create OLTs')
    def createOlts(self, num_olts, num_pon_port, num_onu):
        """
        :param num_olts: Number of OLTs to be created
        :param num_pon_port: Number of PON Ports per OLT
        :param num_onu: Number of ONU per PON Ports
        :return:
        """
        print('*WARN* Warning from a library.')
        return