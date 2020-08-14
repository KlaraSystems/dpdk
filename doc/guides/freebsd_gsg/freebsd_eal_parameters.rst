..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

EAL parameters
==============

This document contains a list of all EAL parameters. These parameters can be
used by any DPDK application running on FreeBSD.

Common EAL parameters
---------------------

The following EAL parameters are common to all platforms supported by DPDK.

.. include:: ../linux_gsg/eal_args.include.rst

FreeBSD-specific EAL parameters
-------------------------------

*   ``--largepage-object <shared memory object path>``

    Use the specified large page object instead of the default /dpdk/largepage.
