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

from subprocess import call, check_call, check_output, CalledProcessError

import glob
import io
import json
import os
import platform
import pwd
import shutil
import six
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from threading import Timer

from charmhelpers.fetch.snap import (
    snap_install,
    snap_refresh,
)
from charmhelpers.core.templating import render
from charmhelpers.core.hookenv import (
    application_version_set,
    charm_dir,
    config,
    ERROR,
    INFO,
    log,
    status_set,
)
from charmhelpers.core.unitdata import kv
from charmhelpers.core.host import (
    add_group,
    add_user_to_group,
    mkdir,
    mount,
    mounts,
    umount,
    service_stop,
    service_start,
    service_restart,
    pwgen,
    lsb_release,
    is_container,
    CompareHostReleases,
)
from charmhelpers.contrib.openstack.utils import (
    is_unit_upgrading_set,
    valid_snap_channel,
)
from charmhelpers.contrib.storage.linux.utils import (
    is_block_device,
    zap_disk,
)
from charmhelpers.contrib.storage.linux.loopback import (
    ensure_loopback_device
)
from charmhelpers.contrib.storage.linux.lvm import (
    create_lvm_volume_group,
    create_lvm_physical_volume,
    list_lvm_volume_group,
    is_lvm_physical_volume,
    deactivate_lvm_volume_group,
    remove_lvm_physical_volume,
)
from charmhelpers.core.decorators import retry_on_exception
from charmhelpers.core.kernel import modprobe
from charmhelpers.fetch import (
    apt_install,
    get_upstream_version
)

BASE_PACKAGES = [
    'btrfs-tools',
    'lvm2',
    'thin-provisioning-tools',
    'criu',
    'zfsutils-linux'
]
LXD_PACKAGES = ['lxd', 'lxd-client']
LXD_SOURCE_PACKAGES = [
    'lxc',
    'lxc-dev',
    'mercurial',
    'git',
    'pkg-config',
    'protobuf-compiler',
    'golang-goprotobuf-dev',
    'build-essential',
    'golang',
    'xz-utils',
    'tar',
    'acl',
]

VERSION_PACKAGE = 'lxd'

LXD_GIT = 'github.com/lxc/lxd'
DEFAULT_LOOPBACK_SIZE = '10G'
PW_LENGTH = 16
ZFS_POOL_NAME = 'lxd'
EXT4_USERNS_MOUNTS = "/sys/module/ext4/parameters/userns_mounts"
# due to bug: 1793137 we have to make this the same as ZFS_POOL_NAME.
LXD_POOL = 'lxd'
VG_NAME = 'lxd_vg'


def install_lxd():
    '''Install LXD'''


def install_lxd_source(user='ubuntu'):
    '''Install LXD from source repositories; installs toolchain first'''
    log('Installing LXD from source')

    home = pwd.getpwnam(user).pw_dir
    GOPATH = os.path.join(home, 'go')
    LXD_SRC = os.path.join(GOPATH, 'src', 'github.com/lxc/lxd')

    if not os.path.exists(GOPATH):
        mkdir(GOPATH)

    env = os.environ.copy()
    env['GOPATH'] = GOPATH
    env['HTTP_PROXY'] = 'http://squid.internal:3128'
    env['HTTPS_PROXY'] = 'https://squid.internal:3128'
    cmd = 'go get -v %s' % LXD_GIT
    log('Installing LXD: %s' % (cmd))
    check_call(cmd, env=env, shell=True)

    if not os.path.exists(LXD_SRC):
        log('Failed to go get %s' % LXD_GIT, level=ERROR)
        raise

    cwd = os.getcwd()
    try:
        os.chdir(LXD_SRC)
        cmd = 'go get -v -d ./...'
        log('Downloading LXD deps: %s' % (cmd))
        call(cmd, env=env, shell=True)

        # build deps
        cmd = 'make'
        log('Building LXD deps: %s' % (cmd))
        call(cmd, env=env, shell=True)
    except Exception:
        log("failed to install lxd")
        raise
    finally:
        os.chdir(cwd)


def configure_lxd_source(user='ubuntu'):
    '''Add required configuration and files when deploying LXD from source'''
    log('Configuring LXD Source')
    home = pwd.getpwnam(user).pw_dir
    GOPATH = os.path.join(home, 'go')

    templates_dir = 'templates'
    render('lxd_upstart', '/etc/init/lxd.conf', {},
           perms=0o644, templates_dir=templates_dir)
    render('lxd_service', '/lib/systemd/system/lxd.service', {},
           perms=0o644, templates_dir=templates_dir)
    add_group('lxd', system_group=True)
    add_user_to_group(user, 'lxd')

    service_stop('lxd')
    files = glob.glob('%s/bin/*' % GOPATH)
    for i in files:
        cmd = ['cp', i, '/usr/bin']
        check_call(cmd)
    service_start('lxd')


def extract_snap_channel(source):
    """Extract the channel from the source, or return None

    :param source: the string from which to extract the channel
    :type source: str
    :returns: the channel or None
    :rtype: Option[str, none]
    """
    if not isinstance(source, six.string_types):
        return None
    if not source.startswith('snap:'):
        return None
    _src = source[5:]
    if '/' in _src:
        channel = _src.split('/')[1]
    else:
        channel = _src
    if valid_snap_channel(channel):
        return _src
    return None


def lxd_snap_channel():
    """Return the current channel being used, or None if the snap is not
    installed.

    :returns: the tracking channel as e.g. stable or 3.0/beta
    :rtype: Option[str, None]
    """
    cmd = "snap info lxd"
    try:
        lines = check_output(cmd.split()).decode('utf-8')
    except CalledProcessError:
        return None
    # now look for a line with "tracking:     <channel>" in it.
    for l in lines.split('\n'):
        if l.startswith("tracking:"):
            return l.split()[1]
    return None


def do_snap_installation(source_channel):
    """Do a snap installation, or refresh the snap if the channel has changed.

    Note, that "lxd.migrate -yes" is run if switching from the packaged version
    to the snap version.  This will also purge the lxd packages if they are
    installed.  Also, the config file for the user (if set) will also be
    moved to the snap location.

    In order to uninstall the lxd packages a lxd-dummy package is installed
    that "Provides: lxd" so that the lxd package can be uninstalled.

    :param source_channel: snap channel to install/refresh/check.
    :type source_channel: str
    """
    log("do_snap_installation ...")
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'xenial':
        status_set("blocked", "Can't install snap on less than xenial release")
        return
    current_channel = lxd_snap_channel()
    log("... current_channel: {}, source_channel: {}".format(current_channel,
                                                             source_channel))
    if current_channel and current_channel != source_channel:
        # do the snap refresh to change to the new channel
        snap_refresh(['lxd'], '--channel', source_channel)
        return
    if current_channel == source_channel:
        return
    snap_install(['lxd'], '--channel', source_channel)
    if current_channel is None:
        try:
            import pexpect
        except ImportError:
            apt_install(['python-pexpect'], fatal=True)
            import pexpect
        log("Running /snap/bin/lxd.migrate via pexpect", INFO)
        child = pexpect.spawn('/snap/bin/lxd.migrate')
        try:
            LXD_Q = (r"Do you want to uninstall the old LXD \(yes/no\) "
                     r"\[default=yes\]\?")
            child.expect(LXD_Q, timeout=300)
            child.sendline('no')
            child.expect(['[$#] ', pexpect.EOF])
        except pexpect.TIMEOUT:
            log("timeout when running lxd.migrate, waiting for prompt", ERROR)
            log("BEFORE:\n{}".format(child.before))
            log("AFTER:\n{}".format(child.after))
            sys.exit(1)
        finally:
            child.close()
        # install the lxd-dummy package so that the lxd and lxd-client packages
        # can be removed, and then purge the lxd and lxd-client packages
        pkg = os.path.join(charm_dir(), 'files', 'lxd-dummy_1.0_all.deb')
        cmds = ("dpkg -i {}".format(pkg),
                "apt purge lxd lxd-client --yes")
        for c in cmds:
            try:
                log("Running {}".format(c), INFO)
                check_call(c.split())
            except CalledProcessError as e:
                log("Error running '{}' due to '{}'".format(c, str(e)), ERROR)
                sys.exit(1)
        # if the migrate command succeeded, see if we need to move any local
        # unit config (we shouldn't have to, but there might be some other set
        # up on the unit in this location that needs moving)
        home = os.environ.get('HOME')
        if home:
            pkg_config_dir = os.path.join(home, '.config/lxc')
            target_parent_dir = os.path.join(home, 'snap/lxd/current/.config')
            target_dir = os.path.join(target_parent_dir, 'lxc')
            if os.path.isdir(pkg_config_dir):
                log("Moving user config {} to {}"
                    .format(pkg_config_dir, target_dir), INFO)
                shutil.rmtree(os.path.join(target_dir), ignore_errors=True)
                shutil.copytree(pkg_config_dir, target_parent_dir)


def get_block_devices():
    """Returns a list of block devices provided by the config."""
    lxd_block_devices = config('block-devices')
    if lxd_block_devices is None:
        return []
    else:
        return lxd_block_devices.split(' ')


def configure_lxd_block():
    '''Configure a block device for use by LXD for containers'''
    log('Configuring LXD container storage')
    if filesystem_mounted('/var/lib/lxd'):
        log('/var/lib/lxd already configured, skipping')
        return

    lxd_block_devices = get_block_devices()
    if len(lxd_block_devices) < 1:
        log('block devices not provided - skipping')
        return
    if len(lxd_block_devices) > 1:
        log("More than one block device is not supported yet, only"
            " using the first")
    lxd_block_device = lxd_block_devices[0]

    dev = None
    if lxd_block_device.startswith('/dev/'):
        dev = lxd_block_device
    elif lxd_block_device.startswith('/'):
        log('Configuring loopback device for use with LXD')
        _bd = lxd_block_device.split('|')
        if len(_bd) == 2:
            dev, size = _bd
        else:
            dev = lxd_block_device
            size = DEFAULT_LOOPBACK_SIZE
        dev = ensure_loopback_device(dev, size)

    if not dev or not is_block_device(dev):
        log('Invalid block device provided: %s' % lxd_block_device)
        return

    # NOTE: check overwrite and ensure its only execute once.
    db = kv()
    if config('overwrite') and not db.get('scrubbed', False):
        clean_storage(dev)
        db.set('scrubbed', True)
        db.flush()

    if not os.path.exists('/var/lib/lxd'):
        mkdir('/var/lib/lxd')

    if config('storage-type') == 'btrfs':
        config_btrfs(dev)
    elif config('storage-type') == 'lvm':
        config_lvm(dev)
    elif config('storage-type') == 'zfs':
        config_zfs(dev)


def config_btrfs(dev):
    status_set('maintenance',
               'Configuring btrfs container storage')
    if has_storage():
        cmd = [lxc_bin(), 'storage', 'create', LXD_POOL, 'btrfs',
               'source={}'.format(dev)]
        check_call(cmd, env=lxc_env())
    else:
        lxd_stop()
        cmd = ['mkfs.btrfs', '-f', dev]
        check_call(cmd)
        mount(dev,
              '/var/lib/lxd',
              options='user_subvol_rm_allowed',
              persist=True,
              filesystem='btrfs')
        cmd = ['btrfs', 'quota', 'enable', '/var/lib/lxd']
        check_call(cmd, env=lxc_env())
        lxd_start()


def config_lvm(dev):
    if (is_lvm_physical_volume(dev) and
            list_lvm_volume_group(dev) == VG_NAME):
        log('Device already configured for LVM/LXD, skipping')
        return
    status_set('maintenance',
               'Configuring LVM container storage')

    cmd = ['systemctl', 'enable', 'lvm2-lvmetad']
    check_call(cmd)
    cmd = ['systemctl', 'start', 'lvm2-lvmetad']
    check_call(cmd)
    if has_storage():
        cmd = [lxc_bin(), 'storage', 'create', LXD_POOL, 'lvm',
               'source={}'.format(dev), 'lvm.vg_name={}'.format(VG_NAME)]
        check_call(cmd, env=lxc_env())
    else:
        create_lvm_physical_volume(dev)
        create_lvm_volume_group(VG_NAME, dev)
        cmd = [lxc_bin(), 'config', 'set', 'storage.lvm_vg_name', VG_NAME]
        check_call(cmd, env=lxc_env())

    # The LVM thinpool logical volume is lazily created, either on
    # image import or container creation. This will force LV creation.
    create_and_import_busybox_image()


def config_zfs(dev):
    status_set('maintenance',
               'Configuring zfs container storage')
    if ZFS_POOL_NAME in zpools():
        log('ZFS pool already exist; skipping zfs configuration')
        return

    if config('overwrite'):
        cmd = ['zpool', 'create', '-f', ZFS_POOL_NAME, dev]
    else:
        cmd = ['zpool', 'create', ZFS_POOL_NAME, dev]
    try:
        check_output(" ".join(cmd),
                     stderr=subprocess.STDOUT,
                     shell=True)
    except CalledProcessError as e:
        log("zpool create failed with {}".format(str(e)), ERROR)
        log("output was '{}'".format(e.output), ERROR)
        if "is in use and contains a unknown filesystem" in e.output:
            # This is BUG#1801349 -- if the kernel has hit this bug the only
            # know solution is to reboot the unit and try again.  The hook
            # should rerun and carry on.  This is a subordinate, and rebooting
            # things is not a great idea, so ONLY do this if overwrite is set,
            # otherwise we error out with a log meesage
            if config('overwrite'):
                log("As config('overwrite') is set, rebooting to get around "
                    "BUG#1801349.", INFO)
                call(["juju-reboot", "--now"])
                log("Rebooting ...", INFO)
                while True:
                    time.sleep(60)
                    log("Still trying to reboot ...", INFO)
            else:
                sys.exit(1)
        import traceback
        log(traceback.format_exc(), ERROR)
        sys.exit(1)

    if has_storage():
        cmd = [lxc_bin(), 'storage', 'create', LXD_POOL, 'zfs',
               "source={}".format(ZFS_POOL_NAME)]
    else:
        cmd = [lxc_bin(), 'config', 'set', 'storage.zfs_pool_name',
               ZFS_POOL_NAME]

    check_call(cmd, env=lxc_env())


def lxc_bin():
    """Return the appropriate lxc binary.  Either the /bin/lxc if it's packaged
    installed, or /snap/bin/lxc if it's snap installed.

    :returns: the path of the lxc binary
    :rtype: str
    """
    if os.path.isfile('/snap/lxd/current/bin/lxc'):
        return '/snap/lxd/current/bin/lxc'
    return '/usr/bin/lxc'


def lxc_env():
    """Return the environment for the lxc command to run in, which if it is the
    snap lxc command will add in the LXD_DIR env to point inside the common
    area of the charm.

    :returns: the environment to run the lxc command in
    :rtype: Dict[str, str]
    """
    env = os.environ.copy()
    if os.path.isfile('/snap/lxd/current/bin/lxc'):
        env['LXD_DIR'] = "/var/snap/lxd/common/lxd/"
    return env


def has_storage():
    try:
        check_call([lxc_bin(), 'storage', 'list'], env=lxc_env())
        return True
    except subprocess.CalledProcessError:
        return False


def create_and_import_busybox_image():
    """Create a busybox image for lxd.

    This creates a busybox image without reaching out to
    the network.

    This function is, for the most part, heavily based on
    the busybox image generation in the pylxd integration
    tests.
    """
    workdir = tempfile.mkdtemp()
    xz = "xz"

    destination_tar = os.path.join(workdir, "busybox.tar")
    target_tarball = tarfile.open(destination_tar, "w:")

    metadata = {'architecture': os.uname()[4],
                'creation_date': int(os.stat("/bin/busybox").st_ctime),
                'properties': {
                    'os': "Busybox",
                    'architecture': os.uname()[4],
                    'description': "Busybox %s" % os.uname()[4],
                    'name': "busybox-%s" % os.uname()[4],
                    # Don't overwrite actual busybox images.
                    'obfuscate': str(uuid.uuid4)}}

    # Add busybox
    with open("/bin/busybox", "rb") as fd:
        busybox_file = tarfile.TarInfo()
        busybox_file.size = os.stat("/bin/busybox").st_size
        busybox_file.mode = 0o755
        busybox_file.name = "rootfs/bin/busybox"
        target_tarball.addfile(busybox_file, fd)

    # Add symlinks
    busybox = subprocess.Popen(["/bin/busybox", "--list-full"],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    busybox.wait()

    for path in busybox.stdout.read().split("\n"):
        if not path.strip():
            continue

        symlink_file = tarfile.TarInfo()
        symlink_file.type = tarfile.SYMTYPE
        symlink_file.linkname = "/bin/busybox"
        symlink_file.name = "rootfs/%s" % path.strip()
        target_tarball.addfile(symlink_file)

    # Add directories
    for path in ("dev", "mnt", "proc", "root", "sys", "tmp"):
        directory_file = tarfile.TarInfo()
        directory_file.type = tarfile.DIRTYPE
        directory_file.name = "rootfs/%s" % path
        target_tarball.addfile(directory_file)

    # Add the metadata file
    metadata_yaml = json.dumps(metadata, sort_keys=True,
                               indent=4, separators=(',', ': '),
                               ensure_ascii=False).encode('utf-8') + b"\n"

    metadata_file = tarfile.TarInfo()
    metadata_file.size = len(metadata_yaml)
    metadata_file.name = "metadata.yaml"
    target_tarball.addfile(metadata_file,
                           io.BytesIO(metadata_yaml))

    inittab = tarfile.TarInfo()
    inittab.size = 1
    inittab.name = "/rootfs/etc/inittab"
    target_tarball.addfile(inittab, io.BytesIO(b"\n"))

    target_tarball.close()

    # Compress the tarball
    r = subprocess.call([xz, "-9", destination_tar])
    if r:
        raise Exception("Failed to compress: %s" % destination_tar)

    image_file = destination_tar+".xz"

    cmd = [lxc_bin(), 'image', 'import', image_file, '--alias', 'busybox']
    check_call(cmd, env=lxc_env())

    shutil.rmtree(workdir)


def determine_packages(snap_install=False):
    """Determine which packages to install

    :param snap_install: If True, then the snap version of packages is needed
    :type snap_install: bool
    """
    packages = list(set(BASE_PACKAGES[:]))

    # criu package doesn't exist for arm64/s390x prior to artful
    machine = platform.machine()
    if (CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'artful' and
            (machine == 'arm64' or machine == 's390x')):
        packages.remove('criu')

    if snap_install:
        return packages

    if config('use-source'):
        packages.extend(LXD_SOURCE_PACKAGES)
    else:
        packages.extend(LXD_PACKAGES)
    return packages


def filesystem_mounted(fs):
    return fs in [f for f, m in mounts()]


def lxd_trust_password():
    db = kv()
    password = db.get('lxd-password')
    if not password:
        password = db.set('lxd-password', pwgen(PW_LENGTH))
        db.flush()
    return password


def configure_lxd_remote(settings, user='root'):
    cmd = ['sudo', '-u', user,
           lxc_bin(), 'remote', 'list']
    output = check_output(cmd, env=lxc_env())
    if settings['hostname'] not in output:
        log('Adding new remote {hostname}:{address}'.format(**settings))
        cmd = ['sudo', '-u', user,
               lxc_bin(), 'remote', 'add',
               settings['hostname'],
               'https://{}:8443'.format(settings['address']),
               '--accept-certificate',
               '--password={}'.format(settings['password'])]
        check_call(cmd, env=lxc_env())
    else:
        log('Updating remote {hostname}:{address}'.format(**settings))
        cmd = ['sudo', '-u', user,
               lxc_bin(), 'remote', 'set-url',
               settings['hostname'],
               'https://{}:8443'.format(settings['address'])]
        check_call(cmd, env=lxc_env())


@retry_on_exception(5, base_delay=2, exc_type=CalledProcessError)
def configure_lxd_host():
    ubuntu_release = lsb_release()['DISTRIB_CODENAME'].lower()
    cmp_ubuntu_release = CompareHostReleases(ubuntu_release)
    if cmp_ubuntu_release > "vivid":
        log('>= Wily deployment - configuring LXD trust password and address',
            level=INFO)
        cmd = [lxc_bin(), 'config', 'set',
               'core.trust_password', lxd_trust_password()]
        check_call(cmd, env=lxc_env())
        cmd = [lxc_bin(), 'config', 'set',
               'core.https_address', '[::]']
        check_call(cmd, env=lxc_env())

        if not is_container():
            # NOTE(jamespage): None of the below is worth doing when running
            #                  within a container on an all-in-one install

            # Configure live migration
            if cmp_ubuntu_release == 'xenial':
                apt_install('linux-image-extra-%s' % os.uname()[2],
                            fatal=True)

            if cmp_ubuntu_release >= 'xenial':
                modprobe('netlink_diag')

            # Enable/disable use of ext4 within nova-lxd containers
            if os.path.exists(EXT4_USERNS_MOUNTS):
                with open(EXT4_USERNS_MOUNTS, 'w') as userns_mounts:
                    userns_mounts.write(
                        'Y\n' if config('enable-ext4-userns') else 'N\n'
                    )

        configure_uid_mapping()
    elif cmp_ubuntu_release == "vivid":
        log('Vivid deployment - loading overlay kernel module', level=INFO)
        cmd = ['modprobe', 'overlay']
        check_call(cmd)
        with open('/etc/modules', 'r+') as modules:
            if 'overlay' not in modules.read():
                modules.write('overlay')


def clean_storage(block_device):
    '''Ensures a block device is clean.  That is:
        - unmounted
        - any lvm volume groups are deactivated
        - any lvm physical device signatures removed
        - partition table wiped

    :param block_device: str: Full path to block device to clean.
    '''
    for mp, d in mounts():
        if d == block_device:
            log('clean_storage(): Found %s mounted @ %s, unmounting.' %
                (d, mp))
            umount(mp, persist=True)

    if is_lvm_physical_volume(block_device):
        deactivate_lvm_volume_group(block_device)
        remove_lvm_physical_volume(block_device)

    zap_disk(block_device)


def lxd_running():
    '''Check whether LXD is running or not'''
    cmd = ['pgrep', 'lxd']
    try:
        check_call(cmd)
        return True
    except CalledProcessError:
        return False


def lxd_stop():
    '''Stop LXD.socket and lxd.service'''
    cmd = ['systemctl', 'stop', 'lxd.socket']
    check_call(cmd)
    cmd = ['systemctl', 'stop', 'lxd']
    check_call(cmd)


def lxd_start():
    cmd = ['systemctl', 'start', 'lxd']
    check_call(cmd)


def assess_status():
    '''Determine status of current unit'''
    if is_unit_upgrading_set():
        status_set('blocked',
                   'Ready for do-release-upgrade and reboot. '
                   'Set complete when finished.')
    elif lxd_running():
        status_set('active', 'Unit is ready')
    else:
        status_set('blocked', 'LXD is not running')
    application_version_set(get_lxd_version())


def get_lxd_version():
    """Get the lxd version depending on whether it's snap installed or pkg
    installed

    :returns: the version number
    :rtype: str
    """
    channel = lxd_snap_channel()
    if channel is not None:
        return "snap:{}".format(channel)
    return get_upstream_version(VERSION_PACKAGE)


def zpools():
    '''
    Query the currently configured ZFS pools

    @return: list of strings of pool names
    '''
    try:
        zpools = check_output(['zpool', 'list', '-H']).splitlines()
        pools = []
        for l in zpools:
            pools.append(l.split()[0])
        return pools
    except CalledProcessError:
        return []


SUBUID = '/etc/subuid'
SUBGID = '/etc/subgid'
DEFAULT_COUNT = '327680000'  # 5000 containers
ROOT_USER = 'root'


def configure_uid_mapping():
    '''Extend root user /etc/{subuid,subgid} mapping for LXD use'''
    restart_lxd = False
    for uidfile in (SUBUID, SUBGID):
        with open(uidfile, 'r+') as f_id:
            ids = []
            for s_id in f_id.readlines():
                _id = s_id.strip().split(':')
                if (_id[0] == ROOT_USER and
                        _id[2] != DEFAULT_COUNT):
                    _id[2] = DEFAULT_COUNT
                    restart_lxd = True
                ids.append(_id)
            f_id.seek(0)
            for _id in ids:
                f_id.write('{}:{}:{}\n'.format(*_id))
            f_id.truncate()
    if restart_lxd:
        # NOTE: restart LXD to pickup changes in id map config
        do_restart_lxd()


def do_restart_lxd():
    """Restart the pkg or snap version of lxd"""
    if get_lxd_version().startswith('snap:'):
        try:
            # this seems to take a long time, so wait up to 10 mins before
            # erroring out
            # TODO(ajkavanagh) when charm is upgraded to python 3, we can do
            # this:
            # check_call(['snap', 'restart', 'lxd'], timeout=600)
            # unfortunately, timeout doesn't exist on Python 2.7, so instead we
            # have to do this:
            restart = subprocess.Popen(['snap', 'restart', 'lxd'],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            timer = Timer(600, lambda p: p.kill(), [restart])
            timer.start()
            restart.communicate()
        except Exception as e:
            log("Couldn't restart snap lxd: '{}'".format(str(e)))
            sys.exit(1)
        finally:
            timer.cancel()
    else:
        service_restart('lxd')
