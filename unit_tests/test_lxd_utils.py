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
