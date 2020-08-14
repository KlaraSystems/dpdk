/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_errno.h>

#include "eal_private.h"
#include "eal_thread.h"

int eal_create_cpu_map(void);

struct cpu_info {
	int domain;
};

static struct cpu_info cpu_info[RTE_MAX_LCORE];

unsigned
eal_cpu_core_id(__rte_unused unsigned lcore_id)
{
	return lcore_id;
}

static int
eal_get_ncpus(void)
{
	static int ncpu = -1;
	int mib[2] = {CTL_HW, HW_NCPU};
	size_t len = sizeof(ncpu);

	if (ncpu < 0) {
		(void)sysctl(mib, 2, &ncpu, &len, NULL, 0);
		RTE_LOG(INFO, EAL, "Sysctl reports %d cpus\n", ncpu);
	}
	return ncpu;
}

static int
eal_get_ndomains(void)
{
	static int ndomains = -1;
	size_t len = sizeof(ndomains);

	if (ndomains < 0) {
		(void)sysctlbyname("vm.ndomains", &ndomains, &len, NULL, 0);
		RTE_LOG(INFO, EAL, "Sysctl reports %d NUMA domains\n", ndomains);
	}
	return ndomains;
}

unsigned
eal_cpu_socket_id(__rte_unused unsigned cpu_id)
{
	return cpu_info[cpu_id].domain;
}

/* Check if a cpu is present by the presence of the
 * cpu information for it.
 */
int
eal_cpu_detected(unsigned lcore_id)
{
	const unsigned ncpus = eal_get_ncpus();
	return lcore_id < ncpus;
}

int
eal_create_cpu_map(void)
{
	cpuset_t set;
	int cpu, ndomains = eal_get_ndomains();

	for (int i = 0; i < ndomains; i++) {
		if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_DOMAIN, i,
		    sizeof(set), &set) != 0) {
			rte_errno = errno;
			return -1;
		}
		while (!CPU_EMPTY(&set)) {
			cpu = CPU_FFS(&set) - 1;
			CPU_CLR(cpu, &set);
			cpu_info[cpu].domain = i;
		}
	}
	return 0;
}
