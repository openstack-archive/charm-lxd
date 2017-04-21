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
    filesystem_mounted,
    determine_packages,
    install_lxd_source,
    configure_lxd_source,
    configure_lxd_block,
    lxd_trust_password,
    configure_lxd_remote,
    configure_lxd_host,
    assess_status,
    has_storage,
    LXD_POOL,
)

from charmhelpers.fetch import (
    apt_update,
    apt_install,
    add_source,
)

hooks = Hooks()


@hooks.hook()
def install():
    status_set('maintenance', 'Installing LXD packages')
    if config('source'):
        add_source(config('source'))
    apt_update(fatal=True)
    apt_install(determine_packages(), fatal=True)
    if config('use-source'):
        install_lxd_source()
        configure_lxd_source()


@hooks.hook()
def config_changed():
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


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log("Unknown hook {} - skipping.".format(e))
    assess_status()

if __name__ == "__main__":
    main()
