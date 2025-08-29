/* Copyright (C) 2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \defgroup utilpool Pool
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Pool utility functions
 */
#include <stdlib.h>

#include "base.h"
#include "common/common.h"
#include "threads.h"
#include "util-debug.h"
#include "util-pool-thread.h"
#include "util-pool.h"

/**
 *  \brief per thread Pool, initialization function
 *  \param thread number of threads this is for. Can start with 1 and be
 * expanded. Other params are as for PoolInit()
 */
PoolThread *PoolThreadInit(int threads, uint32_t size, uint32_t prealloc_size,
        uint32_t elt_size,  void *(*Alloc)(void), int (*Init)(void *, void *),
        void *InitData,  void (*Cleanup)(void *), void (*Free)(void *))
{
    if (threads <= 0) {
        SCLogDebug("error");
        return NULL;
    }

    PoolThread *pt = calloc(1, sizeof(*pt));
    if (unlikely(pt == NULL)) {
        SCLogDebug("memory alloc error");
        goto error;
    }

    SCLogDebug("size %d", threads);
    pt->array = malloc(threads * sizeof(PoolThreadElement));
    if (pt->array == NULL) {
        SCLogDebug("memory alloc error");
        goto error;
    }
    pt->size = threads;

    for (int i = 0; i < threads; i++) {
        PoolThreadElement *e = &pt->array[i];

        SCMutexInit(&e->lock, NULL);
        SCMutexLock(&e->lock);
//        SCLogDebug("size %u prealloc_size %u elt_size %u Alloc %p Init %p InitData %p Cleanup %p Free %p",
//                size, prealloc_size, elt_size,
//                Alloc, Init, InitData, Cleanup, Free);
        e->pool = PoolInit(size, prealloc_size, elt_size, Alloc, Init, InitData, Cleanup, Free);
        SCMutexUnlock(&e->lock);
        if (e->pool == NULL) {
            SCLogDebug("error");
            goto error;
        }
    }

    return pt;
error:
    if (pt != NULL)
        PoolThreadFree(pt);
    return NULL;
}

/** \brief expand pool by one for a new thread
 *  \retval -1 or pool thread id
 */
int PoolThreadExpand(PoolThread *pt)
{
    if (pt == NULL || pt->array == NULL || pt->size == 0) {
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }

    size_t newsize = pt->size + 1;
    SCLogDebug("newsize %"PRIuMAX, (uintmax_t)newsize);

    void *ptmp = realloc(pt->array, (newsize * sizeof(PoolThreadElement)));
    if (ptmp == NULL) {
        free(pt->array);
        pt->array = NULL;
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }
    pt->array = ptmp;
    pt->size = newsize;

    /* copy settings from first thread that registered the pool */
    Pool settings;
    memset(&settings, 0x0, sizeof(settings));
    PoolThreadElement *e = &pt->array[0];
    SCMutexLock(&e->lock);
    settings.max_buckets = e->pool->max_buckets;
    settings.preallocated = e->pool->preallocated;
    settings.elt_size = e->pool->elt_size;
    settings.Alloc = e->pool->Alloc;
    settings.Init = e->pool->Init;
    settings.InitData = e->pool->InitData;
    settings.Cleanup = e->pool->Cleanup;
    settings.Free = e->pool->Free;
    SCMutexUnlock(&e->lock);

    e = &pt->array[newsize - 1];
    memset(e, 0x00, sizeof(*e));
    SCMutexInit(&e->lock, NULL);
    SCMutexLock(&e->lock);
    e->pool = PoolInit(settings.max_buckets, settings.preallocated,
            settings.elt_size, settings.Alloc, settings.Init, settings.InitData,
            settings.Cleanup, settings.Free);
    SCMutexUnlock(&e->lock);
    if (e->pool == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }

    return (int)(newsize - 1);
}

int PoolThreadSize(PoolThread *pt)
{
    if (pt == NULL)
        return -1;
    return (int)pt->size;
}

void PoolThreadFree(PoolThread *pt)
{
    if (pt == NULL)
        return;

    if (pt->array != NULL) {
        for (int i = 0; i < (int)pt->size; i++) {
            PoolThreadElement *e = &pt->array[i];
            SCMutexLock(&e->lock);
            PoolFree(e->pool);
            SCMutexUnlock(&e->lock);
            SCMutexDestroy(&e->lock);
        }
        free(pt->array);
    }
    free(pt);
}

void *PoolThreadGetById(PoolThread *pt, uint16_t id)
{
    void *data = NULL;

    if (pt == NULL || id >= pt->size)
        return NULL;

    PoolThreadElement *e = &pt->array[id];
    SCMutexLock(&e->lock);
    data = PoolGet(e->pool);
    SCMutexUnlock(&e->lock);
    if (data) {
        PoolThreadReserved *did = data;
        *did = id;
    }

    return data;
}

void PoolThreadReturn(PoolThread *pt, void *data) {
  PoolThreadReserved *id = data;

  if (pt == NULL || *id >= pt->size)
    return;

  SCLogDebug("returning to id %u", *id);

  PoolThreadElement *e = &pt->array[*id];
  SCMutexLock(&e->lock);
  PoolReturn(e->pool, data);
  SCMutexUnlock(&e->lock);
}
