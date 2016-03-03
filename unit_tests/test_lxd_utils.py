"""Tests for hooks.lxd_utils."""
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
            'thin-provisioning-tools',
            'criu',
            'lvm2',
            'lxd',
            'lxd-client',
        ]

        packages = lxd_utils.determine_packages()

        self.assertEqual(expected, packages)
