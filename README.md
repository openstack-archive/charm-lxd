# Overview

LXD is a hypervisor for managing Linux Containers; it provides a
simple RESTful API for creation and management of containers. This
charm is currently specific to LXD's use with nova-lxd, but that's
only by usage, rather than specific design.

# Usage with nova-compute and nova-lxd

While the lxd charm can be used with any charm to enable use of LXD,
its primary use is with the nova-compute Openstack charm, for
provisioning LXD based OpenStack Nova instances.

For example:

    juju deploy nova-compute
    juju config nova-compute virt-type=lxd
    juju deploy lxd
    juju config lxd block-devices=/dev/sdb storage-type=lvm
    juju add-relation lxd nova-compute

The caveat is that nova-compute is part of a greater ecosystem of many
OpenStack service charms. For a full OpenStack Mitaka deployment using
LXD, please refer to the [OpenStack
LXD](https://jujucharms.com/u/openstack-charmers-next/openstack-lxd)
bundle.

At this time, nova-lxd is only supported on Ubuntu 16.04 or above, with
OpenStack Mitaka (provided as part of Ubuntu 16.04).

# LXD installation sources

The LXD payload can be installed from either distro, snap or a Github source.
These are via the `source` and `use-source` options.  If `use-source` is `true`
then LXD is installed from the *master* branch of LXD.  This should only be
done for experimentation.

Otherwise, the `source` configuration value can be a package source or snap source:

- A snap source is defined by setting source as `snap:<channel>` where
  `<channel>` is replaced with the desired channel.  Note, that whilst it
  should always be possible to move to later software, it may not be possible
  to return to an earlier version on a compute unit.  The `source` option
  should be considered an *install* time value, although modifying it *will*
  cause a change as part of the `config-changed` hook.

- A package source is defined, as previously, as either `distro`, `proposed`,
  `distro-proposed`, `ppa:<ppa-name>`, `http://...` (suitable for
  `add-apt-repository -yes http://...`), `cloud-archive:<spec>`, or
  `cloud:<release>[-staging]`.

The default setting is `distro` to maintain compatibility with previous
installations of the LXD charm.  From Ubuntu disco (19.04), the package
version of LXD will install the snap.  It is not known how long this will
continue.  The `snap:<channel>` install is provided to access more recent
versions of LXD and to access LXD regardless of how it is installed.

## Migration from package to snap version of LXD

If the `source` config value is changed for an existing node to
`snap:<channel>`, then the LXD charm will install the snap version of LXD,
remove the package version of LXD and run the `lxd.migrate` command.  This
*stops* all of the containers on the node, and moves (if necessary) any local
configuration (drives, network) to the snap configuration locations.  The
containers are then restarted.  This cannot be reversed by setting the config
back to a package installation; this will result in a blocked charm, although
the containers will continue operating.  The charm is *blocked* in the sense
that the configuration for the source can't be used, and will persist until it
is changed back to `snap:<channel>`.

The config for the *nova* user (`/var/lib/nova/.config/lxc/`) is also copied to
the snapped location (`/var/lib/nova/snap/lxd/current/.config/lxc`).  This is
only performed if the target directory doesn't exist.

**Note: due to a limitation in snapd and home directories in /var/lib/ nova-lxd
and lxd are configured to use the *package* location for configuration
(`/var/lib/nova/.config/lxc`) and not the snapped version.  This is done by
running the `lxc` binary directly.  This may change in the future, and will be
noted in this README.**

# Contact Information

Report bugs on [Launchpad](https://bugs.launchpad.net/charm-lxd/+filebug)
