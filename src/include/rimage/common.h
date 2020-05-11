/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Intel Corporation. All rights reserved.
 */

#ifndef __RIMAGE_COMMON_H__
#define __RIMAGE_COMMON_H__

#ifndef ALIGN_UP
#define ALIGN_UP(size, alignment) \
	((size) + (((alignment) - ((size) % (alignment))) % (alignment)))
#endif

#ifndef max
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#endif

#ifndef min
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

#endif /* __RIMAGE_COMMON_H__ */