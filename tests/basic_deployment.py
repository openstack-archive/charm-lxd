# Basic functional black-box test
# See tests/README before modifying or adding new tests.

import amulet

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)

u = OpenStackAmuletUtils(DEBUG)


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
            'block-device': '/dev/vdb',
            'ephemeral-unmount': '/mnt',
            'storage-type': 'lvm'
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

        # Access the sentries for inspecting service units
        self.lxd0_sentry = self.d.sentry['lxd'][0]
        self.lxd1_sentry = self.d.sentry['lxd'][1]
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
            self.lxd1_sentry: ['lxd'],
            self.compute0_sentry: ['nova-compute',
                                   'nova-network',
                                   'nova-api'],
            self.compute1_sentry: ['nova-compute',
                                   'nova-network',
                                   'nova-api'],
            self.mysql_sentry: ['mysql'],
            self.rabbitmq_sentry: ['rabbitmq-server'],
            self.nova_cc_sentry: ['nova-api-ec2',
                                  'nova-api-os-compute',
                                  'nova-objectstore',
                                  'nova-conductor',
                                  'nova-cert',
                                  'nova-scheduler'],
            self.keystone_sentry: ['keystone'],
            self.glance_sentry: ['glance-registry',
                                 'glance-api']
        }

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        u.log.debug('Checking keystone service catalog...')

        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}

        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}

        if self._get_openstack_release() >= self.precise_folsom:
            endpoint_vol['id'] = u.not_null
            endpoint_id['id'] = u.not_null

        expected = {
            'compute': [endpoint_vol],
            'identity': [endpoint_id]
        }

        if self._get_openstack_release() < self.trusty_kilo:
            expected.update({
                's3': [endpoint_vol],
                'ec2': [endpoint_vol]
            })

        actual = self.keystone_demo.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

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

# TODO:  Add bi-directional lxd service relation introspection
    def test_200_nova_compute_shared_db_relation(self):
        """Verify the nova-compute to mysql shared-db relation data"""
        u.log.debug('Checking n-c:mysql db relation data...')

        unit = self.compute0_sentry
        relation = ['shared-db', 'mysql:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'nova_database': 'nova',
            'nova_username': 'nova',
            'nova_hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_mysql_nova_compute_shared_db_relation(self):
        """Verify the mysql to nova-compute shared-db relation data"""
        u.log.debug('Checking mysql:n-c db relation data...')
        unit = self.mysql_sentry
        relation = ['shared-db', 'nova-compute:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'nova_password': u.not_null,
            'db_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_204_nova_compute_amqp_relation(self):
        """Verify the nova-compute to rabbitmq-server amqp relation data"""
        u.log.debug('Checking n-c:rmq amqp relation data...')
        unit = self.compute0_sentry
        relation = ['amqp', 'rabbitmq-server:amqp']
        expected = {
            'username': 'nova',
            'private-address': u.valid_ip,
            'vhost': 'openstack'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_rabbitmq_nova_compute_amqp_relation(self):
        """Verify the rabbitmq-server to nova-compute amqp relation data"""
        u.log.debug('Checking rmq:n-c amqp relation data...')
        unit = self.rabbitmq_sentry
        relation = ['amqp', 'nova-compute:amqp']
        expected = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('rabbitmq amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_208_nova_compute_cloud_compute_relation(self):
        """Verify the nova-compute to nova-cc cloud-compute relation data"""
        u.log.debug('Checking n-c:n-c-c cloud-compute relation data...')
        unit = self.compute0_sentry
        relation = ['cloud-compute', 'nova-cloud-controller:cloud-compute']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_210_nova_cc_cloud_compute_relation(self):
        """Verify the nova-cc to nova-compute cloud-compute relation data"""
        u.log.debug('Checking n-c-c:n-c cloud-compute relation data...')
        unit = self.nova_cc_sentry
        relation = ['cloud-compute', 'nova-compute:cloud-compute']
        expected = {
            'volume_service': 'cinder',
            'network_manager': 'flatdhcpmanager',
            'ec2_host': u.valid_ip,
            'private-address': u.valid_ip,
            'restart_trigger': u.not_null
        }
        if self._get_openstack_release() == self.precise_essex:
            expected['volume_service'] = 'nova-volume'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_nova_compute_config(self):
        """Verify the data in the nova-compute config file."""
        u.log.debug('Checking nova-compute config file data...')
        units = [self.compute0_sentry, self.compute1_sentry]
        conf = '/etc/nova/nova-compute.conf'

        expected = {
            'DEFAULT': {
                'compute_driver': 'nclxd.nova.virt.lxd.LXDDriver'
            }
        }

        for unit in units:
            for section, pairs in expected.iteritems():
                ret = u.validate_config_data(unit, conf, section, pairs)
                if ret:
                    message = "nova config error: {}".format(ret)
                    amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_nova_compute_nova_config(self):
        """Verify the data in the nova config file."""
        u.log.debug('Checking nova config file data...')
        units = [self.compute0_sentry, self.compute1_sentry]
        conf = '/etc/nova/nova.conf'
        rmq_nc_rel = self.rabbitmq_sentry.relation('amqp',
                                                   'nova-compute:amqp')
        gl_nc_rel = self.glance_sentry.relation('image-service',
                                                'nova-compute:image-service')
        db_nc_rel = self.mysql_sentry.relation('shared-db',
                                               'nova-compute:shared-db')
        db_uri = "mysql://{}:{}@{}/{}".format('nova',
                                              db_nc_rel['nova_password'],
                                              db_nc_rel['db_host'],
                                              'nova')
        expected = {
            'DEFAULT': {
                'dhcpbridge_flagfile': '/etc/nova/nova.conf',
                'dhcpbridge': '/usr/bin/nova-dhcpbridge',
                'logdir': '/var/log/nova',
                'state_path': '/var/lib/nova',
                'force_dhcp_release': 'True',
                'verbose': 'False',
                'use_syslog': 'False',
                'ec2_private_dns_show_ip': 'True',
                'api_paste_config': '/etc/nova/api-paste.ini',
                'enabled_apis': 'ec2,osapi_compute,metadata',
                'auth_strategy': 'keystone',
                'flat_interface': 'eth1',
                'network_manager': 'nova.network.manager.FlatDHCPManager',
                'volume_api_class': 'nova.volume.cinder.API',
            },
            'oslo_concurrency': {
                'lock_path': '/var/lock/nova'
            },
            'database': {
                'connection': db_uri
            },
            'oslo_messaging_rabbit': {
                'rabbit_userid': 'nova',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rmq_nc_rel['password'],
                'rabbit_host': rmq_nc_rel['hostname'],
            },
            'glance': {
                'api_servers': gl_nc_rel['glance-api-server']
            }
        }

        for unit in units:
            for section, pairs in expected.iteritems():
                ret = u.validate_config_data(unit, conf, section, pairs)
                if ret:
                    message = "nova config error: {}".format(ret)
                    amulet.raise_status(amulet.FAIL, msg=message)

# TODO:  use lxd image instead.
# Will fail as-is with cirros image (because there is no KVM hypervisor).
# ie. message: No valid host was found. There are not enough hosts available.

    def FIXME_test_400_image_instance_create(self):
        """Create an image/instance, verify they exist, and delete them."""
        u.log.debug('Checking nova instance creation...')

        image = u.create_cirros_image(self.glance, "cirros-image")
        if not image:
            amulet.raise_status(amulet.FAIL, msg="Image create failed")

        instance = u.create_instance(self.nova_demo, "cirros-image", "cirros",
                                     "m1.tiny")
        if not instance:
            amulet.raise_status(amulet.FAIL, msg="Instance create failed")

        found = False
        for instance in self.nova_demo.servers.list():
            if instance.name == 'cirros':
                found = True
                if instance.status != 'ACTIVE':
                    msg = "cirros instance is not active"
                    amulet.raise_status(amulet.FAIL, msg=msg)

        if not found:
            message = "nova cirros instance does not exist"
            amulet.raise_status(amulet.FAIL, msg=message)

        u.delete_resource(self.glance.images, image.id,
                          msg="glance image")

        u.delete_resource(self.nova_demo.servers, instance.id,
                          msg="nova instance")

# TODO:  Add more 4xx functional tests.
#   Inspect lvs, vgs, lsblk?
#   Snapshot, live migrate, etc.

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed."""
        u.log.debug('Checking service restart on charm config '
                    'option change...')

        sentry = self.compute0_sentry
        juju_service = 'nova-compute'

        # Expected default and alternate values
        set_default = {'verbose': 'False'}
        set_alternate = {'verbose': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        conf_file = '/etc/nova/nova.conf'
        services = {
            # ?:
            'lxd': conf_file,
            'nova-compute': conf_file,
            'nova-api': conf_file,
            'nova-network': conf_file
        }

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 30
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     sleep_time=sleep_time):

                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            sleep_time = 0

        self.d.configure(juju_service, set_default)
