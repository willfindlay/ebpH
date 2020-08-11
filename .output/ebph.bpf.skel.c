/*
 * pybpf - A ebph_bpf CO-RE (Compile Once Run Everywhere) wrapper for Python3
 * Copyright (C) 2020  William Findlay
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 *
 * 2020-Aug-02  William Findlay  Created this. */

#include <bpf/libbpf.h>
#include <sys/resource.h>

#include "/home/housedhorse/documents/projects/ebpH/.output/ebph.bpf.skel.h"

void pybpf_destroy(struct ebph_bpf *bpf)
{
    ebph_bpf__destroy(bpf);
}

struct ebph_bpf *pybpf_open(void)
{
    return ebph_bpf__open();
}

int pybpf_load(struct ebph_bpf *bpf)
{
    return ebph_bpf__load(bpf);
}

int pybpf_attach(struct ebph_bpf *bpf)
{
    return ebph_bpf__attach(bpf);
}

struct bpf_object *get_bpf_object(struct ebph_bpf *bpf)
{
    if (!bpf) {
        return NULL;
    }

    return bpf->obj;
}

int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}
