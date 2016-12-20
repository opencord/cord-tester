import sys

class readProperties(object):
    def __init__(self, strPropertiesFile):
        self.strPropertiesFile = strPropertiesFile

    @staticmethod
    def parse_line(input):
        key, value = input.split('=',1)
        key = key.strip()
        value = value.strip()
        return key, value

    @staticmethod
    def getProperties(self):
        data = {}

        with open(self.strPropertiesFile) as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('import'):
                   continue

                key, value = readProperties.parse_line(line)
                data[key] = value

        return data

    def getValueProperties(self, key):
        datas = readProperties.getProperties(self)
        value = datas[key]
        return value

#test
#test = readProperties("testProperties.py")
#test.getValueProperties("CORE_INSTANCES")
