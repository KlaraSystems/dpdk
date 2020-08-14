/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <sys/types.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <string.h>

#include <rte_log.h>
#include <fcntl.h>

#include "eal_private.h"
#include "eal_hugepages.h"
#include "eal_internal_cfg.h"
#include "eal_filesystem.h"

#define DEFAULT_LARGEPAGE_OBJECT "/dpdk/largepage"

/*
 * Uses mmap to create a shared memory area for storage of data
 * Used in this file to store the hugepage file map on disk
 */
static void *
map_shared_memory(const char *filename, const size_t mem_size, int flags)
{
	void *retval;
	int fd = open(filename, flags, 0600);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, mem_size) < 0) {
		close(fd);
		return NULL;
	}
	retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	return retval;
}

static void *
open_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, O_RDWR);
}

static void *
create_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, O_RDWR | O_CREAT);
}

int
eal_hugepage_info_init(void)
{
	char path[PATH_MAX];
	struct hugepage_info *hpi;
	struct internal_config *internal_conf = eal_get_internal_configuration();
	struct shm_largepage_conf lpc;
	struct stat sb;
	unsigned i;
	size_t ps[MAXPAGESIZES];
	int fd, pscnt;

	pscnt = getpagesizes(ps, MAXPAGESIZES);
	if (pscnt < 0) {
		RTE_LOG(ERR, EAL, "Could not fetch page sizes array\n");
		return -1;
	}

	/* 2MB or 1GB only. */
	internal_conf->num_hugepage_sizes = pscnt - 1;

	if (internal_conf->largepage_object != NULL)
		(void)snprintf(path, sizeof(path), "%s",
		    internal_conf->largepage_object);
	else
		(void)snprintf(path, sizeof(path), "%s",
		    DEFAULT_LARGEPAGE_OBJECT);

	fd = shm_open(path, O_RDWR, 0);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "Failed to open large page object %s: %s\n",
		    path, strerror(errno));
		return -1;
	}
	if (ioctl(fd, FIOGSHMLPGCNF, &lpc) != 0) {
		RTE_LOG(ERR, EAL, "Failed to obtain large page info from %s: %s\n",
		    path, strerror(errno));
		(void)close(fd);
		return -1;
	}
	if (fstat(fd, &sb) != 0) {
		RTE_LOG(ERR, EAL, "Failed to stat %s: %s\n", path, strerror(errno));
		(void)close(fd);
		return -1;
	}

	/* Record all pages as being in domain 0 for now, they will be sorted
	 * later.
	 */
	hpi = &internal_conf->hugepage_info[lpc.psind - 1];
	(void)strlcpy(hpi->hugedir, path, sizeof(hpi->hugedir));
	hpi->hugepage_sz = ps[lpc.psind];
	hpi->num_pages[0] = sb.st_size / ps[lpc.psind];
	hpi->lock_descriptor = fd;

	/* for no shared files mode, do not create shared memory config */
	if (internal_conf->no_shconf)
		return 0;

	struct hugepage_info *tmp_hpi = create_shared_memory(eal_hugepage_info_path(),
			sizeof(internal_conf->hugepage_info));
	if (tmp_hpi == NULL ) {
		RTE_LOG(ERR, EAL, "Failed to create shared memory!\n");
		return -1;
	}

	memcpy(tmp_hpi, internal_conf->hugepage_info,
	       sizeof(internal_conf->hugepage_info));

	/* we've copied file descriptors along with everything else, but they
	 * will be invalid in secondary process, so overwrite them
	 */
	for (i = 0; i < RTE_DIM(internal_conf->hugepage_info); i++) {
		struct hugepage_info *tmp = &tmp_hpi[i];
		tmp->lock_descriptor = -1;
	}

	if (munmap(tmp_hpi, sizeof(internal_conf->hugepage_info)) < 0) {
		RTE_LOG(ERR, EAL, "Failed to unmap shared memory!\n");
		return -1;
	}
	return 0;
}

/* copy stuff from shared info into internal config */
int
eal_hugepage_info_read(void)
{
	struct internal_config *internal_conf =
		eal_get_internal_configuration();

	struct hugepage_info *hpi = &internal_conf->hugepage_info[0];
	struct hugepage_info *tmp_hpi;

	internal_conf->num_hugepage_sizes = 1;

	tmp_hpi = open_shared_memory(eal_hugepage_info_path(),
				  sizeof(internal_conf->hugepage_info));
	if (tmp_hpi == NULL) {
		RTE_LOG(ERR, EAL, "Failed to open shared memory!\n");
		return -1;
	}

	memcpy(hpi, tmp_hpi, sizeof(internal_conf->hugepage_info));

	if (munmap(tmp_hpi, sizeof(internal_conf->hugepage_info)) < 0) {
		RTE_LOG(ERR, EAL, "Failed to unmap shared memory!\n");
		return -1;
	}
	return 0;
}
