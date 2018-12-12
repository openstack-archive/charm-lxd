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

At this time, nova-lxd is only supported on Ubuntu 16.04 or above,
with OpenStack Mitaka (provided as part of Ubuntu 16.04).

# Contact Information

Report bugs on [Launchpad](https://bugs.launchpad.net/charm-lxd/+filebug)