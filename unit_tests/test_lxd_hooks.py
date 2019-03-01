# -*- coding: utf-8 -*-
# Copyright 2019 Canonical Ltd
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


"""Tests for hooks.lxd_hooks.py"""
import testing

import lxd_hooks


class TestInstallHook(testing.CharmTestCase):
    """Tests for hooks.lxd_hooks.install."""

    TO_PATCH = [
        'add_source',
        'apt_install',
        'apt_update',
        'config',
        'configure_lxd_source',
        'determine_packages',
        'do_snap_installation',
        'extract_snap_channel',
        'install_lxd_source',
        'status_set',
    ]

    def setUp(self):
        super(TestInstallHook, self).setUp(
            lxd_hooks, self.TO_PATCH)
        self.config.side_effect = self.test_config.get

    def test_install_pkg(self):
        """Test that the pkg version calls the right things"""
        self.test_config.set('use-source', False)
        self.test_config.set('source', "")
        self.extract_snap_channel.return_value = None
        self.determine_packages.return_value = ['hello']

        lxd_hooks.install()
        self.status_set.assert_called_once_with(
            'maintenance', 'Installing packages')
        self.add_source.assert_not_called()
        self.determine_packages.assert_called_once_with(snap_install=False)
        self.apt_update.assert_called_once_with(fatal=True)
        self.apt_install.assert_called_once_with(['hello'], fatal=True)
        self.do_snap_installation.assert_not_called()
        self.install_lxd_source.assert_not_called()
        self.configure_lxd_source.assert_not_called()

    def test_install_pkg_non_standard(self):
        """Test that pkg install with source calls the right things"""
        self.test_config.set('use-source', False)
        self.test_config.set('source', 'special-distro')
        self.extract_snap_channel.return_value = None
        self.determine_packages.return_value = ['thing']

        lxd_hooks.install()
        self.add_source.assert_called_once_with('special-distro')
        self.apt_update.assert_called_once_with(fatal=True)
        self.determine_packages.assert_called_once_with(snap_install=False)
        self.apt_install.assert_called_once_with(['thing'], fatal=True)
        self.do_snap_installation.assert_not_called()
        self.install_lxd_source.assert_not_called()
        self.configure_lxd_source.assert_not_called()

    def test_install_from_source(self):
        """Test that install from source works"""
        self.test_config.set('use-source', True)
        self.test_config.set('source', '')
        self.extract_snap_channel.return_value = None
        self.determine_packages.return_value = ['thing']

        lxd_hooks.install()
        self.add_source.assert_not_called()
        self.apt_update.assert_called_once_with(fatal=True)
        self.determine_packages.assert_called_once_with(snap_install=False)
        self.apt_install.assert_called_once_with(['thing'], fatal=True)
        self.do_snap_installation.assert_not_called()
        self.install_lxd_source.assert_called_once_with()
        self.configure_lxd_source.assert_called_once_with()

    def test_install_snap(self):
        """Test that install from a snap does the right thing"""
        self.test_config.set('use-source', False)
        self.test_config.set('source', 'snap:3.0/stable')
        self.extract_snap_channel.return_value = "3.0/stable"
        self.determine_packages.return_value = ['thing']

        lxd_hooks.install()
        self.extract_snap_channel.assert_called_once_with("snap:3.0/stable")
        self.add_source.assert_not_called()
        self.apt_update.assert_called_once_with(fatal=True)
        self.determine_packages.assert_called_once_with(snap_install=True)
        self.do_snap_installation.assert_called_once_with('3.0/stable')
        self.install_lxd_source.assert_not_called()
        self.configure_lxd_source.assert_not_called()


class TestConfigChangedHook(testing.CharmTestCase):
    """Tests for hooks.lxd_hooks.config_changed."""

    TO_PATCH = [
        'config',
        'lxd_snap_channel',
        'extract_snap_channel',
        'do_snap_installation',
        'filesystem_mounted',
        'configure_lxd_block',
        'configure_lxd_host',
        'umount',
    ]

    def setUp(self):
        super(TestConfigChangedHook, self).setUp(
            lxd_hooks, self.TO_PATCH)
        self.config.side_effect = self.test_config.get

    def test_config_no_snap(self):
        """Test that the config_changed hook ignores channels if not set"""
        self.lxd_snap_channel.return_value = None
        self.extract_snap_channel.return_value = None
        self.test_config.set('source', '')
        self.test_config.set('ephemeral-unmount', '')
        lxd_hooks.config_changed()

        self.extract_snap_channel.assert_called_once_with("")
        self.do_snap_installation.assert_not_called()
        self.filesystem_mounted.assert_not_called()
        self.umount.assert_not_called()
        self.configure_lxd_block.assert_called_once_with()
        self.configure_lxd_host.assert_called_once_with()

    def test_config_snap_existing_pkg(self):
        """Test that config_changed can install a snap from a pkg installed
        system"""
        self.lxd_snap_channel.return_value = None
        self.extract_snap_channel.return_value = "stable"
        self.test_config.set('source', "snap:stable")
        self.test_config.set('ephemeral-unmount', '')
        lxd_hooks.config_changed()

        self.extract_snap_channel.assert_called_once_with('snap:stable')
        self.do_snap_installation.assert_called_once_with('stable')

    def test_config_snap_changed_channel(self):
        """Test that config-changed can swap the snap channel"""
        self.lxd_snap_channel.return_value = 'beta'
        self.extract_snap_channel.return_value = "stable"
        self.test_config.set('source', "snap:stable")
        self.test_config.set('ephemeral-unmount', '')
        lxd_hooks.config_changed()

        self.extract_snap_channel.assert_called_once_with('snap:stable')
        self.do_snap_installation.assert_called_once_with('stable')

    def test_config_snap_unchanged_channel(self):
        """Test that config-changed doesn't do snap if channel not changed"""
        self.lxd_snap_channel.return_value = 'stable'
        self.extract_snap_channel.return_value = "stable"
        self.test_config.set('source', "snap:stable")
        self.test_config.set('ephemeral-unmount', '')
        lxd_hooks.config_changed()

        self.extract_snap_channel.assert_called_once_with('snap:stable')
        self.do_snap_installation.assert_not_called()
