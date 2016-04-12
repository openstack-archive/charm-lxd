# Overview

LXD is a hypervisor for managing Linux Containers; it provides a simple RESTful API for creation and management of containers.

# Usage

The lxd charm can be used in-conjunction with any principle charm to setup and enable use of LXD; its primary use case is with the nova-compute charm to enable LXD based OpenStack Clouds:

    juju deploy cs:~openstack-charmers-next/wily/nova-compute
    juju set nova-compute virt-type=lxd
    juju deploy cs:~openstack-charmers-next/wily/lxd
    juju set lxd block-devices=/dev/sdb storage-type=lvm
    juju add-relation lxd nova-compute

At this point in time, LXD is only supported on Ubuntu 15.10 or above, in-conjunction with OpenStack Liberty (provided as part of Ubuntu 15.10).

For a full OpenStack Liberty deployment using LXD, please refer to the [OpenStack LXD](https://jujucharms.com/u/openstack-charmers-next/openstack-lxd) bundle.

# Contact Information

Report bugs on [Launchpad](http://bugs.launchpad.net/charms/+source/lxd/+filebug)
