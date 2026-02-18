.. SPDX-License-Identifier: GPL-2.0

===================
Root namespace uAPI
===================

Creation
--------

Root namespace creation involves the following steps:

1. ``rootns_create()`` creates a control file for a rootns that tracks
   namespaces, credentials, root path, member tasks and lifecycle state.
2. Namespace creation starts from an empty mount namespace for which the root
   file system is installed by means of ``FSCONFIG_SET_ROOTNS`` and
   ``MOVE_MOUNT_T_ROOTNS_ROOT``.
3. The first successful ``rootns_enter()`` call commits the entering task as the
   init task for the rootns.

Further ``rootns_enter()`` calls admit additional member tasks while the rootns
is alive.

Mounting constraints
--------------------

``MOVE_MOUNT_T_ROOTNS_ROOT`` requires a rootns fd as the destination and uses
additional checks when installing the initial root mount:

1. The source must be a mounted directory and the root of a detached anonymous
   mount namespace.
2. nsfs loop checks are enforced before attaching the tree.
3. The caller must have ``CAP_SYS_ADMIN`` in the destination rootns owner's
   user namespace.
4. The destination rootns may only be initialized once.
5. LSM checks are still applied via ``security_move_mount()``; rootns creation
   itself is guarded by ``security_rootns_alloc()``.

Namespace mutation constraints
------------------------------

The rootns fd is the only way to admit new tasks from outside of the rootns.
Once admitted, tasks may create nested namespaces inside the rootns domain:

1. ``clone()``/``clone3()`` with ``CLONE_NEW*`` flags creates children that
   remain rootns members.
2. ``unshare()`` of those same namespace classes creates namespaces derived
   from the task's current rootns membership.
3. ``setns()`` may join namespaces that were created inside the same rootns
   domain, or rejoin the task's current namespace.

``setns()`` of namespaces outside of the rootns domain fails with ``-EPERM`` so
a task cannot bypass the membership, credentials, root directory and lifecycle
setup done by ``rootns_enter()``.

A self-contained rootns should be created with ``ROOTNS_ALL_NAMESPACES`` so
namespace state is not intentionally shared with its creator.

System call API
---------------

.. kernel-doc:: include/uapi/linux/rootns.h
   :doc: Root namespace system calls

Creation flags
--------------

.. kernel-doc:: include/uapi/linux/rootns.h
   :doc: Root namespace flags
