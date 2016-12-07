# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for hooks.lxd_utils."""
import mock

import lxd_utils
import testing


class TestLXDUtilsDeterminePackages(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.determine_packages."""

    TO_PATCH = [
        'config',
    ]

    def setUp(self):
        super(TestLXDUtilsDeterminePackages, self).setUp(
            lxd_utils, self.TO_PATCH)
        self.config.side_effect = self.test_config.get

    def test_determine_packages(self):
        """A list of LXD packages should be returned."""
        expected = [
            'btrfs-tools',
            'criu',
            'lvm2',
            'lxd',
            'lxd-client',
            'thin-provisioning-tools',
            'zfsutils-linux',
        ]

        packages = lxd_utils.determine_packages()

        self.assertEqual(expected, sorted(packages))


class TestLXDUtilsCreateAndImportBusyboxImage(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.create_and_import_busybox_image."""

    TO_PATCH = []

    def setUp(self):
        super(TestLXDUtilsCreateAndImportBusyboxImage, self).setUp(
            lxd_utils, self.TO_PATCH)

    @mock.patch('lxd_utils.open')
    @mock.patch('lxd_utils.os.stat')
    @mock.patch('lxd_utils.subprocess.Popen')
    @mock.patch('lxd_utils.shutil.rmtree')
    @mock.patch('lxd_utils.subprocess.call')
    @mock.patch('lxd_utils.tarfile.open')
    @mock.patch('lxd_utils.tempfile.mkdtemp')
    @mock.patch('lxd_utils.check_call')
    def test_create_and_import_busybox_image(
            self, check_call, mkdtemp, tarfile_open, subprocess_call,
            rmtree, Popen, stat, mock_open):
        """A busybox image is imported into lxd."""
        mkdtemp.return_value = '/not/a/real/path'
        tarfile_open.return_value = mock.Mock()
        subprocess_call.return_value = False
        Popen_rv = mock.Mock()
        Popen_rv.stdout.read.return_value = '\n'
        Popen.return_value = Popen_rv
        stat_rv = mock.Mock()
        stat_rv.st_ctime = 0
        stat_rv.st_size = 0
        stat.return_value = stat_rv

        lxd_utils.create_and_import_busybox_image()

        self.assertTrue(check_call.called)
        args = check_call.call_args[0][0]
        self.assertEqual(['lxc', 'image', 'import'], args[:3])
        self.assertEqual(['--alias', 'busybox'], args[4:])

        # Assert all other mocks *would* have been called.
        mkdtemp.assert_called_once_with()
        tarfile_open.assert_called_once_with(
            '/not/a/real/path/busybox.tar', 'w:')
        subprocess_call.assert_called_once_with(
            ['xz', '-9', '/not/a/real/path/busybox.tar'])
        Popen.assert_called_once_with(
            ['/bin/busybox', '--list-full'], stdout=-1,
            universal_newlines=True)
        Popen_rv.stdout.read.assert_called_once_with()
        stat.assert_called_with('/bin/busybox')
        mock_open.assert_called_once_with('/bin/busybox', 'rb')


class TestGetBlockDevices(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.get_block_devices."""

    TO_PATCH = [
        'config',
    ]

    def setUp(self):
        super(TestGetBlockDevices, self).setUp(
            lxd_utils, self.TO_PATCH)
        self.config.side_effect = self.test_config.get

    def testEmpty(self):
        """When no config is specified, an empty list is returned."""
        devices = lxd_utils.get_block_devices()

        self.assertEqual([], devices)

    def testSingleDevice(self):
        """Return a list with the single device."""
        self.test_config.set('block-devices', '/dev/vdb')
        devices = lxd_utils.get_block_devices()

        self.assertEqual(['/dev/vdb'], devices)

    def testMultipleDevices(self):
        """Return a list with all devices."""
        self.test_config.set('block-devices', '/dev/vdb /dev/vdc')

        devices = lxd_utils.get_block_devices()

        self.assertEqual(['/dev/vdb', '/dev/vdc'], devices)


ZFS_SINGLE_POOL = """testpool    232G    976M    231G    -    7%    0%    1.04x    ONLINE    -
"""

ZFS_MULTIPLE_POOLS = """testpool    232G    976M    231G    -    7%    0%    1.04x    ONLINE    -
testpool2    232G    976M    231G    -    7%    0%    1.04x    ONLINE    -
"""


class TestZFSPool(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.zpools"""
    TO_PATCH = [
        'check_output',
    ]

    def setUp(self):
        super(TestZFSPool, self).setUp(lxd_utils, self.TO_PATCH)

    def test_no_pools(self):
        """When no pools are configured, an empty list is returned"""
        self.check_output.return_value = ""
        self.assertEqual(lxd_utils.zpools(), [])

    def test_single_pool(self):
        """Return a list with a single pool"""
        self.check_output.return_value = ZFS_SINGLE_POOL
        self.assertEqual(lxd_utils.zpools(), ['testpool'])

    def test_multiple_pools(self):
        """Return a list with a multiple pools"""
        self.check_output.return_value = ZFS_MULTIPLE_POOLS
        self.assertEqual(lxd_utils.zpools(), ['testpool', 'testpool2'])


class TestLXDUtilsAssessStatus(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.assess_status."""

    TO_PATCH = [
        'application_version_set',
        'get_upstream_version',
        'status_set',
        'lxd_running',
    ]

    def setUp(self):
        super(TestLXDUtilsAssessStatus, self).setUp(
            lxd_utils, self.TO_PATCH)
        self.get_upstream_version.return_value = '2.0.1'

    def test_assess_status_active(self):
        '''When LXD is running, ensure active is set'''
        self.lxd_running.return_value = True
        lxd_utils.assess_status()
        self.status_set.assert_called_with('active',
                                           'Unit is ready')
        self.application_version_set.assert_called_with('2.0.1')
        self.get_upstream_version.assert_called_with(
            lxd_utils.VERSION_PACKAGE
        )

    def test_assess_status_blocked(self):
        '''When LXD is not running, ensure blocked is set'''
        self.lxd_running.return_value = False
        lxd_utils.assess_status()
        self.status_set.assert_called_with('blocked',
                                           'LXD is not running')
        self.application_version_set.assert_called_with('2.0.1')
        self.get_upstream_version.assert_called_with(
            lxd_utils.VERSION_PACKAGE
        )


class TestConfigureUIDGID(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.configure_uid_mapping."""

    TO_PATCH = [
        'check_call',
        'service_restart'
    ]

    UIDMAP = [
        'lxd:100000:65536',
        'root:100000:65536',
        'ubuntu:165536:65536',
    ]

    def setUp(self):
        super(TestConfigureUIDGID, self).setUp(
            lxd_utils, self.TO_PATCH)

    def test_configure_uid_mapping(self):
        with testing.patch_open() as (_open, _file):
            _file.readlines.return_value = self.UIDMAP
            lxd_utils.configure_uid_mapping()
            _open.assert_has_calls([
                mock.call('/etc/subuid', 'r+'),
                mock.call('/etc/subgid', 'r+')
            ])
            _file.write.assert_has_calls([
                mock.call('lxd:100000:65536\n'),
                mock.call('root:100000:327680000\n'),
                mock.call('ubuntu:165536:65536\n')
            ])
        self.service_restart.assert_called_with('lxd')
