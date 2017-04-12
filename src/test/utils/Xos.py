import os,time
from CordContainer import Container
from CordTestUtils import log_test

class XosBase(object):
    workspace = '/tmp/xos_scratch_workspace'
    image = 'xosproject/xos'
    tag = 'latest'

    @classmethod
    def clone(cls, update = False):
        fetch_cmd = 'mkdir -p {} && cd {} && \
                     git clone http://gerrit.opencord.org/xos'.format(cls.workspace, cls.workspace)
        fetch = True
        if os.access(cls.workspace, os.F_OK):
            fetch = update
            if update is True:
                os.system('rm -rf {}'.format(cls.workspace))
        if fetch is True:
            ##fetch the xos
            os.system(fetch_cmd)

    @classmethod
    def build_images(cls):
        images = ( ['xos', ('base', 'build',),],
                   ['postgresql', ('build',),],
                   ['synchronizer', ('build',),],
                   ['onboarding_synchronizer', ('build',),],
                   ['syndicate-ms', ('build',),],
                  )

        for cnt, targets in images:
            for target in targets:
                xos_dir = 'cd {}/xos/containers/{} && make {}'.format(cls.workspace, cnt, target)
                os.system(xos_dir)

class XosServiceProfile(XosBase):

    def __init__(self, profile = 'cord-pod', update = False):
        self.workspace = XosBase.workspace
        self.profile = profile
        self.service_dir = '{}/service-profile'.format(self.workspace)
        self.profile_dir = '{}/{}'.format(self.service_dir, profile)
        XosBase.clone(update = update)
        self.__clone(update = update)

    def __clone(self, update = False):
        fetch_cmd = 'cd {} && git clone http://gerrit.opencord.org/service-profile'.format(self.workspace)
        fetch = True
        if os.access(self.service_dir, os.F_OK):
            fetch = update
            if update is True:
                os.system('rm -rf {}'.format(self.service_dir))
        if fetch:
            os.system(fetch_cmd)

    def __ssh_key_check(self):
        id_rsa = '{}/.ssh/id_rsa'.format(os.getenv('HOME'))
        if not os.access(id_rsa, os.F_OK):
            return False
        return True

    def __ssh_copy_keys(self, dest):
        cmd = 'cp -v {}/.ssh/id_rsa* {}'.format(os.getenv('HOME'), dest)
        return os.system(cmd)

    def build_images(self, force = False):
        if force is True or not Container.image_exists('{}:{}'.format(XosBase.image, XosBase.tag)):
            XosBase.build_images()

    def start_services(self):
        if not self.__ssh_key_check():
            log_test.info('SSH keys need to be generated before building XOS service containers')
            log_test.info('Use the following commands to generate ssh keys')
            log_test.info('ssh-keygen -t rsa -q -N ""')
            log_test.info('ssh-copy-id -i $HOME/.ssh/id_rsa ubuntu@localhost')
            return False
        if not os.access(self.profile_dir, os.F_OK):
            log_test.error('Profile directory %s does not exist' %self.profile_dir)
            return False
        self.build_images()
        ##copy the keys to the profile dir
        self.__ssh_copy_keys(self.profile_dir)
        service_cmd = 'cd {} && make dirs download_services bootstrap onboarding'.format(self.profile_dir)
        return os.system(service_cmd)

    def stop_services(self, rm = False):
        if os.access(self.profile_dir, os.F_OK):
            cmds = ['cd {}'.format(self.profile_dir), 'make stop']
            if rm is True:
                cmds += ['make rm']
            cmd = ' && '.join(cmds)
            return os.system(cmd) == 0
        return False
