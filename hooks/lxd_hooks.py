#!/usr/bin/env python
#
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

from socket import gethostname
import sys
import uuid

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    unit_get,
    relation_set,
    relation_get,
    relation_ids,
    related_units,
    status_set,
)

from charmhelpers.core.host import (
    umount,
    add_user_to_group,
)

from lxd_utils import (
    assess_status,
    configure_lxd_block,
    configure_lxd_host,
    configure_lxd_remote,
    configure_lxd_source,
    determine_packages,
    do_snap_installation,
    extract_snap_channel,
    filesystem_mounted,
    has_storage,
    install_lxd_source,
    LXD_POOL,
    lxd_snap_channel,
    lxd_trust_password,
)

from charmhelpers.fetch import (
    apt_update,
    apt_install,
    add_source,
)

from charmhelpers.contrib.openstack.utils import (
    clear_unit_paused,
    clear_unit_upgrading,
    set_unit_paused,
    set_unit_upgrading,
)

hooks = Hooks()


@hooks.hook('install.real')
def install():
    log("starting the install hook -- python")
    status_set('maintenance', 'Installing packages')
    source = config('source') or ""
    if source and not source.startswith('snap:'):
        add_source(config('source'))
    apt_update(fatal=True)
    channel = extract_snap_channel(source)
    log("source: {}, channel={}".format(source, channel))
    is_snap_install = channel is not None
    apt_install(determine_packages(snap_install=is_snap_install),
                fatal=True)
    if is_snap_install:
        do_snap_installation(channel)
        return
    if config('use-source'):
        install_lxd_source()
        configure_lxd_source()


@hooks.hook()
def config_changed():
    current_channel = lxd_snap_channel()
    source = config('source') or ""
    channel = extract_snap_channel(source)
    if current_channel != channel:
        do_snap_installation(channel)
    e_mountpoint = config('ephemeral-unmount')
    if e_mountpoint and filesystem_mounted(e_mountpoint):
        umount(e_mountpoint)
    configure_lxd_block()
    configure_lxd_host()


@hooks.hook('lxd-migration-relation-joined')
def lxd_relation_joined(rid=None):
    settings = {}
    settings['password'] = lxd_trust_password()
    settings['hostname'] = gethostname()
    settings['address'] = unit_get('private-address')
    if has_storage():
        settings['pool'] = LXD_POOL
    relation_set(relation_id=rid,
                 relation_settings=settings)


@hooks.hook('lxd-relation-changed')
def lxd_relation_changed():
    user = relation_get('user')
    if user:
        add_user_to_group(user, 'lxd')
        for rid in relation_ids('lxd'):
            relation_set(relation_id=rid,
                         nonce=uuid.uuid4())
        # Re-fire lxd-migration relation to ensure that
        # remotes have been setup for the user
        for rid in relation_ids('lxd-migration'):
            for unit in related_units(rid):
                lxd_migration_relation_changed(rid, unit)


@hooks.hook('lxd-migration-relation-changed')
def lxd_migration_relation_changed(rid=None, unit=None):
    settings = {
        'password': relation_get('password',
                                 rid=rid,
                                 unit=unit),
        'hostname': relation_get('hostname',
                                 rid=rid,
                                 unit=unit),
        'address': relation_get('address',
                                rid=rid,
                                unit=unit),
    }
    if all(settings.values()):
        users = ['root']
        for rid in relation_ids('lxd'):
            for unit in related_units(rid):
                user = relation_get(attribute='user',
                                    rid=rid,
                                    unit=unit)
                if user:
                    users.append(user)
        users = list(set(users))
        [configure_lxd_remote(settings, u) for u in users]


@hooks.hook('pre-series-upgrade')
def pre_series_upgrade():
    log("Running prepare series upgrade hook", "INFO")
    # NOTE: The Ceph packages handle the series upgrade gracefully.
    # In order to indicate the step of the series upgrade process for
    # administrators and automated scripts, the charm sets the paused and
    # upgrading states.
    set_unit_paused()
    set_unit_upgrading()


@hooks.hook('post-series-upgrade')
def post_series_upgrade():
    log("Running complete series upgrade hook", "INFO")
    # In order to indicate the step of the series upgrade process for
    # administrators and automated scripts, the charm clears the paused and
    # upgrading states.
    clear_unit_paused()
    clear_unit_upgrading()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))
    assess_status()


if __name__ == "__main__":
    main()
