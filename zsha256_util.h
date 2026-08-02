/*
 * Copyright 2022 Ye Jiaqiang <yejq.jiaqiang@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Adapted from: https://blog.csdn.net/maxzero/article/details/81773443
 *
 * Simple SHA256 Implementation in C
 */

#ifndef _M_ZSHA256_H
#define _M_ZSHA256_H 1

/* request definitions for uint8_t/uint32_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZSHA256_BLKSIZE    64
#define ZSHA256_STRSIZE    (64 + 8)
#define ZSHA256_DONE       0xFFFFFFFFu

struct zsha256 {
	uint32_t hashlen;
	uint32_t hashval[8];
};

void zsha256_init(struct zsha256 * hash);

int zsha256_update(struct zsha256 * hash,
	const uint8_t * srcp, uint32_t srclen);

int zsha256_final(struct zsha256 * hash,
	const uint8_t * srcp, uint32_t srclen);

const char * zsha256_hex(
	char * pbuf, uint32_t buflen,
	const struct zsha256 * hash);

#ifdef __cplusplus
}
#endif
#endif
