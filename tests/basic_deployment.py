# Basic functional black-box test
# See tests/README before modifying or adding new tests.

import amulet
import time

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

# NOTE(beisner):
#   LXDAmuletUtils inherits and extends OpenStackAmuletUtils, with
#   the intention of ultimately moving the relevant helpers into
#   OpenStackAmuletUtils.
#
# from charmhelpers.contrib.openstack.amulet.utils import (
#     OpenStackAmuletUtils,
from lxd_amulet_utils import (
    LXDAmuletUtils,
    DEBUG,
)


u = LXDAmuletUtils(DEBUG)

LXD_IMAGE_URL = 'http://cloud-images.ubuntu.com/trusty/current/trusty-server-cloudimg-amd64-root.tar.xz'  # noqa
LXD_IMAGE_NAME = 'trusty-server-cloudimg-amd64-root.tar.xz'


class LXDBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic nova compute deployment."""

    def __init__(self, series=None, openstack=None, source=None,
                 stable=False):
        """Deploy the test environment."""
        super(LXDBasicDeployment, self).__init__(series, openstack,
                                                 source, stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        exclude_services = ['mysql']
        self._auto_wait_for_status(exclude_services=exclude_services)

        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where lxd is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'lxd'}

        other_services = [{'name': 'mysql'},
                          {'name': 'nova-compute', 'units': 2},
                          {'name': 'rabbitmq-server'},
                          {'name': 'nova-cloud-controller'},
                          {'name': 'keystone'},
                          {'name': 'glance'}]

        super(LXDBasicDeployment, self)._add_services(this_service,
                                                      other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'lxd:lxd': 'nova-compute:lxd',
            'nova-compute:image-service': 'glance:image-service',
            'nova-compute:shared-db': 'mysql:shared-db',
            'nova-compute:amqp': 'rabbitmq-server:amqp',
            'nova-cloud-controller:shared-db': 'mysql:shared-db',
            'nova-cloud-controller:identity-service': 'keystone:'
                                                      'identity-service',
            'nova-cloud-controller:amqp': 'rabbitmq-server:amqp',
            'nova-cloud-controller:cloud-compute': 'nova-compute:'
                                                   'cloud-compute',
            'nova-cloud-controller:image-service': 'glance:image-service',
            'keystone:shared-db': 'mysql:shared-db',
            'glance:identity-service': 'keystone:identity-service',
            'glance:shared-db': 'mysql:shared-db',
            'glance:amqp': 'rabbitmq-server:amqp'
        }
        super(LXDBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        nova_cc_config = {
            'ram-allocation-ratio': '5.0'
        }

        lxd_config = {
            'block-devices': '/dev/vdb',
            'ephemeral-unmount': '/mnt',
            'storage-type': 'lvm',
            'overwrite': True
        }

        nova_config = {
            'config-flags': 'auto_assign_floating_ip=False',
            'enable-live-migration': True,
            'enable-resize': True,
            'migration-auth-type': 'ssh',
            'virt-type': 'lxd'
        }

        keystone_config = {
            'admin-password': 'openstack',
            'admin-token': 'ubuntutesting'
        }

        configs = {
            'nova-compute': nova_config,
            'lxd': lxd_config,
            'keystone': keystone_config,
            'nova-cloud-controller': nova_cc_config
        }

        super(LXDBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""

        u.log.debug(self.d.sentry['lxd'])
        # Access the sentries for inspecting service units
        self.lxd0_sentry = self.d.sentry['lxd'][0]
        # XXX: rockstar (6 Mar 2016) - Due to what might be an amulet
        # bug, it's possible that we only detect a single lxd instance.
        # Either that, or something drastically more nefarious is going
        # on. In order to move ahead, this hack is put in place.
        # See https://github.com/juju/amulet/issues/122
        try:
            self.lxd1_sentry = self.d.sentry['lxd'][1]
        except IndexError:
            self.lxd1_sentry = None
        self.compute0_sentry = self.d.sentry['nova-compute'][0]
        self.compute1_sentry = self.d.sentry['nova-compute'][1]

        self.mysql_sentry = self.d.sentry['mysql'][0]
        self.keystone_sentry = self.d.sentry['keystone'][0]
        self.rabbitmq_sentry = self.d.sentry['rabbitmq-server'][0]
        self.nova_cc_sentry = self.d.sentry['nova-cloud-controller'][0]
        self.glance_sentry = self.d.sentry['glance'][0]

        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))

        # Authenticate admin with keystone
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with glance endpoint
        self.glance = u.authenticate_glance_admin(self.keystone)

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)
            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user,
                                       password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

        # Authenticate demo user with keystone
        self.keystone_demo = \
            u.authenticate_keystone_user(self.keystone, user=self.demo_user,
                                         password='password',
                                         tenant=self.demo_tenant)

        # Authenticate demo user with nova-api
        self.nova_demo = u.authenticate_nova_user(self.keystone,
                                                  user=self.demo_user,
                                                  password='password',
                                                  tenant=self.demo_tenant)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        u.log.debug('Checking system services on units...')

        services = {
            self.lxd0_sentry: ['lxd'],
            self.compute0_sentry: ['nova-compute',
                                   'nova-network',
                                   'nova-api'],
            self.compute1_sentry: ['nova-compute',
                                   'nova-network',
                                   'nova-api'],
            self.mysql_sentry: ['mysql'],
            self.rabbitmq_sentry: ['rabbitmq-server'],
            self.nova_cc_sentry: ['nova-api-os-compute',
                                  'nova-conductor',
                                  'nova-cert',
                                  'nova-scheduler'],
            self.glance_sentry: ['glance-registry',
                                 'glance-api']
        }
        # XXX: rockstar (6 Mar 2016) - See related XXX comment
        # above.
        if self.lxd1_sentry is not None:
            services[self.lxd1_sentry] = ['lxd']

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

        u.log.debug('Ok')

    def test_104_openstack_compute_api_endpoint(self):
        """Verify the openstack compute api (osapi) endpoint data."""
        u.log.debug('Checking compute endpoint data...')

        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8774'
        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'osapi endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

        u.log.debug('Ok')

    # TODO:  Add bi-directional lxd service relation introspection

    def test_400_check_logical_volume_groups(self):
        """Inspect and validate vgs on all lxd units."""
        u.log.debug('Checking logical volume groups on lxd units...')

        cmd = 'sudo vgs'
        expected = ['lxd_vg']

        invalid = []
        for sentry_unit in self.d.sentry['lxd']:
            host = sentry_unit.info['public-address']
            unit_name = sentry_unit.info['unit_name']

            output, _ = u.run_cmd_unit(sentry_unit, cmd)
            for expected_content in expected:
                if expected_content not in output:
                    invalid.append('{} {} vgs does not contain '
                                   '{}'.format(unit_name, host,
                                               expected_content))

            if invalid:
                u.log.error('Logical volume group check failed.')
                amulet.raise_status(amulet.FAIL, msg='; '.join(invalid))

        u.log.debug('Ok')

    def test_401_check_logical_volumes(self):
        """Inspect and validate lvs on all lxd units."""
        u.log.debug('Checking logical volumes on lxd units...')

        cmd = 'sudo lvs'
        expected = ['LXDPool']

        invalid = []
        for sentry_unit in self.d.sentry['lxd']:
            host = sentry_unit.info['public-address']
            unit_name = sentry_unit.info['unit_name']

            output, _ = u.run_cmd_unit(sentry_unit, cmd)
            for expected_content in expected:
                if expected_content not in output:
                    invalid.append('{} {} lvs does not contain '
                                   '{}'.format(unit_name, host,
                                               expected_content))

            if invalid:
                u.log.error('Logical volume check failed.')
                amulet.raise_status(amulet.FAIL, msg='; '.join(invalid))

        u.log.debug('Ok')

    def test_402_lxc_config_validate(self):
        """Inspect and validate lxc running config on all lxd units."""
        u.log.debug('Checking lxc config on lxd units...')

        cmd = 'sudo lxc config show'
        expected = [
            'core.https_address: \'[::]\'',
            'core.trust_password: true',
            'storage.lvm_thinpool_name: LXDPool',
            'storage.lvm_vg_name: lxd_vg',
        ]

        invalid = []
        for sentry_unit in self.d.sentry['lxd']:
            host = sentry_unit.info['public-address']
            unit_name = sentry_unit.info['unit_name']

            output, _ = u.run_cmd_unit(sentry_unit, cmd)
            for expected_content in expected:
                if expected_content not in output:
                    invalid.append('{} {} lxc config does not contain '
                                   '{}'.format(unit_name, host,
                                               expected_content))

            if invalid:
                u.log.error('lxc config check failed')
                amulet.raise_status(amulet.FAIL, msg='; '.join(invalid))

        u.log.debug('Ok')

    def test_410_image_instance_create(self):
        """Create an image/instance, verify they exist, and delete them."""
        u.log.debug('Create glance image, nova LXD instance...')

        # Add nova key pair
        # TODO:  Nova keypair create

        # Add glance image
        # XXX: rockstar (11 Apr 2016) - It is awkward that we are uploading
        # a rootfs image as raw in glance. This is an issue with nova-lxd
        # itself, and should be fixed soon.
        image = u.glance_create_image(self.glance,
                                      LXD_IMAGE_NAME,
                                      LXD_IMAGE_URL,
                                      disk_format='raw',
                                      hypervisor_type='lxc')
        if not image:
            amulet.raise_status(amulet.FAIL, msg='Image create failed')

        # Create nova instance
        instance_name = 'lxd-instance-{}'.format(time.time())
        instance = u.create_instance(self.nova_demo, LXD_IMAGE_NAME,
                                     instance_name, 'm1.tiny')
        if not instance:
            amulet.raise_status(amulet.FAIL, msg='Nova instance create failed')

        found = False
        for instance in self.nova_demo.servers.list():
            if instance.name == instance_name:
                found = True
                # TODO:  Get instance IP address
                if instance.status != 'ACTIVE':
                    msg = 'Nova instance is not active'
                    amulet.raise_status(amulet.FAIL, msg=msg)

        if not found:
            message = 'Nova instance does not exist'
            amulet.raise_status(amulet.FAIL, msg=message)

        # TODO:  Confirm nova instance:  TCP port knock
        # NOTE(beisner):
        #    This will require additional environment configuration
        #    and post-deployment operation such as network creation
        #    before it can be tested.  The instance has no IP address.
        #
        # host = '1.2.3.4'
        # port = 22
        # timeout = 30
        # connected = u.port_knock_tcp(host, port, timeout)
        # if connected:
        #     u.log.debug('Socket connect OK: {}:{}'.format(host, port))
        # else:
        #     msg = 'Socket connect failed: {}:{}'.format(host, port)
        #     amulet.raise_status(amulet.FAIL, msg)

        # TODO:  ICMP instance ping
        # TODO:  SSH instance login

        # Cleanup
        u.delete_resource(self.glance.images, image.id,
                          msg='glance image')

        u.delete_resource(self.nova_demo.servers, instance.id,
                          msg='nova instance')
        # TODO:  Delete nova keypair

        u.log.debug('Ok')
