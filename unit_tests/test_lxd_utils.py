# -*- coding: utf-8 -*-
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
import subprocess
import sys
import textwrap

import charmhelpers.fetch.snap as snaps

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

    def test_determine_packages_snap_install(self):
        """A list of LXD packages around a snap install should be returned"""
        expected = [
            'btrfs-tools',
            'criu',
            'lvm2',
            'thin-provisioning-tools',
            'zfsutils-linux',
        ]

        packages = lxd_utils.determine_packages(snap_install=True)

        self.assertEqual(expected, sorted(packages))


class TestLXDUtilsCreateAndImportBusyboxImage(testing.CharmTestCase):
    """Tests for hooks.lxd_utils.create_and_import_busybox_image."""

    TO_PATCH = [
        'lxc_bin',
        'lxc_env',
    ]

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
        self.lxc_bin.return_value = 'lxc'
        self.lxc_env.return_value = {}
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
        'lxd_snap_channel',
    ]

    def setUp(self):
        super(TestLXDUtilsAssessStatus, self).setUp(
            lxd_utils, self.TO_PATCH)
        self.get_upstream_version.return_value = '2.0.1'

    def test_assess_status_active(self):
        '''When LXD is running, ensure active is set'''
        self.lxd_running.return_value = True
        self.lxd_snap_channel.return_value = None
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
        self.lxd_snap_channel.return_value = 'stable'
        lxd_utils.assess_status()
        self.status_set.assert_called_with('blocked',
                                           'LXD is not running')
        self.application_version_set.assert_called_with('snap:stable')
        self.get_upstream_version.assert_not_called()


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

    @mock.patch.object(lxd_utils, 'do_restart_lxd')
    def test_configure_uid_mapping(self, mock_do_restart_lxd):
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
        # self.service_restart.assert_called_with('lxd')
        mock_do_restart_lxd.assert_called_once_with()


class TestSnapFunctions(testing.CharmTestCase):
    """Tests the related snap funtions."""

    TO_PATCH = [
        'check_output',
        'get_upstream_version',
    ]

    def setUp(self):
        super(TestSnapFunctions, self).setUp(
            lxd_utils, self.TO_PATCH)

    def test_extract_snap_channel(self):
        """Test that channel gets extracted or returns None if not a channel"""
        self.assertEqual(lxd_utils.extract_snap_channel(None), None)
        self.assertEqual(lxd_utils.extract_snap_channel('ppa:something'), None)
        self.assertEqual(lxd_utils.extract_snap_channel('distro'), None)
        with self.assertRaises(snaps.InvalidSnapChannel):
            lxd_utils.extract_snap_channel('snap:'), None
        self.assertEqual(lxd_utils.extract_snap_channel('snap:stable'),
                         'stable')
        self.assertEqual(lxd_utils.extract_snap_channel('snap:beta'),
                         'beta')
        self.assertEqual(lxd_utils.extract_snap_channel('snap:edge'),
                         'edge')
        self.assertEqual(lxd_utils.extract_snap_channel('snap:a/stable'),
                         'a/stable')
        self.assertEqual(lxd_utils.extract_snap_channel('snap:b/beta'),
                         'b/beta')
        self.assertEqual(lxd_utils.extract_snap_channel('snap:c/edge'),
                         'c/edge')
        with self.assertRaises(snaps.InvalidSnapChannel):
            lxd_utils.extract_snap_channel('snap:thing'), None
        with self.assertRaises(snaps.InvalidSnapChannel):
            lxd_utils.extract_snap_channel('snap:stable/thing'), None

    def test_lxd_snap_channel(self):
        """Test that lxd_snap_channel() can extract the current channel
        installed."""
        lxd_output = textwrap.dedent(
            u"""
            name:      lxd
            summary:   System container manager and API
            publisher: Canonical✓
            contact:   https://github.com/lxc/lxd/issues
            license:   unset
            ...
            snap-id:      J60k4JY0HppjwOjW8dZdYc8obXKxujRu
            tracking:     stable
            refresh-date: yesterday at 15:32 UTC
            channels:
              stable:        3.10        2019-02-11 (10102) 54MB -
              candidate:     3.10        2019-02-11 (10102) 54MB -
              beta:          ↑
              edge:          git-07cbadb 2019-02-14 (10133) 54MB -
              3.0/stable:    3.0.3       2018-11-26  (9663) 53MB -
              3.0/candidate: 3.0.3       2019-01-19  (9942) 53MB -
              3.0/beta:      ↑
              3.0/edge:      git-c0f142d 2019-02-13 (10118) 53MB -
              2.0/stable:    2.0.11      2018-07-30  (8023) 28MB -
              2.0/candidate: 2.0.11      2018-07-27  (8023) 28MB -
              2.0/beta:      ↑
              2.0/edge:      git-c7c4cc8 2018-10-19  (9257) 26MB -
            installed:       3.10                   (10102) 54MB -
            """)
        self.check_output.return_value = lxd_output.encode('utf-8')
        self.assertEqual(lxd_utils.lxd_snap_channel(), "stable")
        self.check_output.assert_called_once_with(['snap', 'info', 'lxd'])
        self.check_output.return_value = "".encode('utf-8')
        self.assertEqual(lxd_utils.lxd_snap_channel(), None)

    @mock.patch('os.path.isfile')
    def test_lxc_bin(self, mock_os_path_isfile):
        """Verify that lxc_bin returns the right value for the bin"""
        mock_os_path_isfile.return_value = False
        self.assertEqual(lxd_utils.lxc_bin(), '/usr/bin/lxc')
        mock_os_path_isfile.return_value = True
        self.assertEqual(lxd_utils.lxc_bin(),
                         '/snap/lxd/current/bin/lxc')

    @mock.patch('os.path.isfile')
    def test_lxc_env(self, mock_os_path_isfile):
        mock_env = {'key': 'value'}
        with mock.patch('os.environ', new=mock_env):
            mock_os_path_isfile.return_value = False
            self.assertEqual(lxd_utils.lxc_env(), mock_env)
            mock_os_path_isfile.return_value = True
            mock_env_snapped = mock_env.copy()
            mock_env_snapped['LXD_DIR'] = '/var/snap/lxd/common/lxd/'
            r_env = lxd_utils.lxc_env()
            self.assertEqual(r_env, mock_env_snapped)
            self.assertFalse('LXD_DIR' in mock_env)

    @mock.patch.object(lxd_utils, 'lxd_snap_channel')
    def test_get_lxd_version(self, mock_lxd_snap_channel):
        """Test the underlying version of lxd is fetched when snapped"""
        mock_lxd_snap_channel.return_value = None
        self.get_upstream_version.return_value = '1'
        self.assertEqual(lxd_utils.get_lxd_version(), '1')
        self.get_upstream_version.assert_called_once_with(
            lxd_utils.VERSION_PACKAGE)
        mock_lxd_snap_channel.return_value = '2'
        self.get_upstream_version.reset_mock()
        self.assertEqual(lxd_utils.get_lxd_version(), 'snap:2')
        self.get_upstream_version.assert_not_called()


class TestDoSnapInstallation(testing.CharmTestCase):
    """Tests the snap installation funtions"""

    TO_PATCH = [
        'apt_install',
        'charm_dir',
        'check_call',
        'log',
        'lsb_release',
        'lxd_snap_channel',
        'snap_install',
        'snap_refresh',
        'status_set',
    ]

    def setUp(self):
        super(TestDoSnapInstallation, self).setUp(
            lxd_utils, self.TO_PATCH)

    @mock.patch('pwd.getpwnam')
    @mock.patch('shutil.rmtree')
    @mock.patch('shutil.copytree')
    @mock.patch('os.path.isdir')
    def test_do_snap_installation_from_pkg_with_migrate(
            self, mock_isdir, mock_copytree, mock_rmtree, mock_getpwnam):
        self.lxd_snap_channel.return_value = None
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'bionic'}
        mock_isdir.side_effect = [True, False]
        self.charm_dir.return_value = '/this'
        pexpect = mock.Mock()
        child = mock.Mock()
        pexpect.spawn.return_value = child

        def _apt_install_side_effect(pkgs, fatal=None):
            assert fatal is True
            assert 'python-pexpect' in pkgs
            assert len(pkgs) == 1
            sys.modules['pexpect'] = pexpect

        self.apt_install.side_effect = _apt_install_side_effect

        mock_pw_dir = mock.Mock(pw_dir='/some/path')
        mock_getpwnam.return_value = mock_pw_dir

        lxd_utils.do_snap_installation('stable')

        self.snap_refresh.not_called()
        self.snap_install.assert_called_once_with(
            ['lxd'], '--channel', 'stable')
        # verify that pexpect stuff happened properly
        pexpect.spawn.assert_called_once_with('/snap/bin/lxd.migrate')
        child_calls = [
            mock.call(r'Do you want to uninstall the old LXD \(yes/no\) '
                      r'\[default=yes\]\?', timeout=300),
            mock.call(['[$#] ', pexpect.EOF])]
        child.expect.assert_has_calls(child_calls)
        child.sendline.assert_called_once_with('no')
        child.close.assert_called_once_with()

        calls = [
            mock.call(['dpkg', '-i', '/this/files/lxd-dummy_1.0_all.deb']),
            mock.call(['apt', 'purge', 'lxd', 'lxd-client', '--yes'])]
        self.check_call.assert_has_calls(calls)
        isdir_calls = [
            mock.call('/some/path/.config/lxc'),
            mock.call('/some/path/snap/lxd/current/.config/lxc')]
        mock_isdir.assert_has_calls(isdir_calls)
        mock_rmtree.assert_called_once_with(
            '/some/path/snap/lxd/current/.config/lxc', ignore_errors=True)
        mock_copytree.assert_called_once_with(
            '/some/path/.config/lxc',
            '/some/path/snap/lxd/current/.config')

    def test_do_snap_installation_existing_channel_different(self):
        self.lxd_snap_channel.return_value = 'beta'
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'bionic'}
        lxd_utils.do_snap_installation('stable')
        self.snap_install.assert_not_called()
        self.snap_refresh.assert_called_once_with(
            ['lxd'], '--channel', 'stable')
        self.check_call.assert_not_called()

    def test_do_snap_installation_existing_channel_same(self):
        self.lxd_snap_channel.return_value = 'stable'
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'bionic'}
        lxd_utils.do_snap_installation('stable')
        self.snap_install.assert_not_called()
        self.snap_refresh.assert_not_called()
        self.check_call.assert_not_called()

    def test_do_snap_installation_blocked_before_xenial(self):
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'wily'}
        lxd_utils.do_snap_installation('stable')
        self.status_set.assert_called_once_with('blocked', mock.ANY)

    def test_do_snap_installation_okay_after_wily(self):
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'xenial'}
        self.lxd_snap_channel.return_value = 'stable'
        lxd_utils.do_snap_installation('stable')
        self.snap_install.assert_not_called()
        self.snap_refresh.assert_not_called()
        self.check_call.assert_not_called()
        self.status_set.assert_not_called()


class TestDoRestartLxd(testing.CharmTestCase):
    """Tests the restart lxd function which has to handle snaps and pkg"""

    TO_PATCH = [
        'get_lxd_version',
        'log',
        'service_restart',
        'Timer',
    ]

    def setUp(self):
        super(TestDoRestartLxd, self).setUp(
            lxd_utils, self.TO_PATCH)

    def test_pkg_restart(self):
        self.get_lxd_version.return_value = '1'
        lxd_utils.do_restart_lxd()
        self.service_restart.assert_called_once_with('lxd')

    @mock.patch('subprocess.Popen')
    def test_snap_restart_no_timeout(self, mock_popen):
        timer = mock.Mock()
        self.Timer.return_value = timer
        restart = mock.Mock()
        mock_popen.return_value = restart
        self.get_lxd_version.return_value = 'snap:2'
        lxd_utils.do_restart_lxd()
        mock_popen.assert_called_once_with(
            ['snap', 'restart', 'lxd'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.Timer.assert_called_once_with(600, mock.ANY, [restart])
        timer.start.assert_called_once_with()
        restart.communicate.assert_called_once_with()
        timer.cancel.assert_called_once_with()

    @mock.patch('sys.exit')
    @mock.patch('subprocess.Popen')
    def test_snap_restart_with_timeout(self, mock_popen, mock_sys_exit):
        timer = mock.Mock()
        self.Timer.return_value = timer
        restart = mock.Mock()
        mock_popen.return_value = restart
        self.get_lxd_version.return_value = 'snap:2'

        def start_side_effect(*args, **kwargs):
            raise Exception("I timed out")
        timer.start.side_effect = start_side_effect
        lxd_utils.do_restart_lxd()
        mock_popen.assert_called_once_with(
            ['snap', 'restart', 'lxd'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.Timer.assert_called_once_with(600, mock.ANY, [restart])
        timer.start.assert_called_once_with()
        timer.cancel.assert_called_once_with()
        mock_sys_exit.assert_called_once_with(1)
