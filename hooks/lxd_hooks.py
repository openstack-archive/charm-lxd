#!/usr/bin/env python

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
    configure_lxd_live_migrate,
    lxd_trust_password,
    configure_lxd_remote,
    configure_lxd_host,
    assess_status,
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
    configure_lxd_live_migrate()


@hooks.hook('lxd-migration-relation-joined')
def lxd_relation_joined(rid=None):
    settings = {}
    settings['password'] = lxd_trust_password()
    settings['hostname'] = gethostname()
    settings['address'] = unit_get('private-address')
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
