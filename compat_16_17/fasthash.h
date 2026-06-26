/*
 * fasthash.h
 *
 * Vendored subset of src/include/common/hashfn_unstable.h from PostgreSQL 17+
 * for use on PostgreSQL 16 where this header does not exist.
 *
 * Only the incremental (streaming) interface is included here. The standalone
 * and C-string helpers are omitted since they are not needed.
 *
 * Original fasthash code from:
 * https://code.google.com/archive/p/fast-hash/source/default/source
 *
 * The MIT License
 *
 * Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef PGSP_FASTHASH_H
#define PGSP_FASTHASH_H

typedef struct fasthash_state
{
	uint64		accum;
	uint64		hash;
} fasthash_state;

#define FH_SIZEOF_ACCUM sizeof(uint64)

static inline void
fasthash_init(fasthash_state *hs, uint64 seed)
{
	memset(hs, 0, sizeof(fasthash_state));
	hs->hash = seed ^ 0x880355f21e6d1965;
}

static inline uint64
fasthash_mix(uint64 h, uint64 tweak)
{
	h ^= (h >> 23) + tweak;
	h *= 0x2127599bf4325c37;
	h ^= h >> 47;
	return h;
}

static inline void
fasthash_combine(fasthash_state *hs)
{
	hs->hash ^= fasthash_mix(hs->accum, 0);
	hs->hash *= 0x880355f21e6d1965;
}

static inline void
fasthash_accum(fasthash_state *hs, const char *k, size_t len)
{
	uint32		lower_four;

	Assert(len <= FH_SIZEOF_ACCUM);
	hs->accum = 0;

#ifdef WORDS_BIGENDIAN
	switch (len)
	{
		case 8:
			memcpy(&hs->accum, k, 8);
			break;
		case 7:
			hs->accum |= (uint64) k[6] << 8;
			/* FALLTHROUGH */
		case 6:
			hs->accum |= (uint64) k[5] << 16;
			/* FALLTHROUGH */
		case 5:
			hs->accum |= (uint64) k[4] << 24;
			/* FALLTHROUGH */
		case 4:
			memcpy(&lower_four, k, sizeof(lower_four));
			hs->accum |= (uint64) lower_four << 32;
			break;
		case 3:
			hs->accum |= (uint64) k[2] << 40;
			/* FALLTHROUGH */
		case 2:
			hs->accum |= (uint64) k[1] << 48;
			/* FALLTHROUGH */
		case 1:
			hs->accum |= (uint64) k[0] << 56;
			break;
		case 0:
			return;
	}
#else
	switch (len)
	{
		case 8:
			memcpy(&hs->accum, k, 8);
			break;
		case 7:
			hs->accum |= (uint64) k[6] << 48;
			/* FALLTHROUGH */
		case 6:
			hs->accum |= (uint64) k[5] << 40;
			/* FALLTHROUGH */
		case 5:
			hs->accum |= (uint64) k[4] << 32;
			/* FALLTHROUGH */
		case 4:
			memcpy(&lower_four, k, sizeof(lower_four));
			hs->accum |= lower_four;
			break;
		case 3:
			hs->accum |= (uint64) k[2] << 16;
			/* FALLTHROUGH */
		case 2:
			hs->accum |= (uint64) k[1] << 8;
			/* FALLTHROUGH */
		case 1:
			hs->accum |= (uint64) k[0];
			break;
		case 0:
			return;
	}
#endif

	fasthash_combine(hs);
}

static inline uint64
fasthash_final64(fasthash_state *hs, uint64 tweak)
{
	return fasthash_mix(hs->hash, tweak);
}

#endif							/* PGSP_FASTHASH_H */
