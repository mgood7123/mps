/* locus.h: GENERATION CHAINS
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 */

#ifndef locus_h
#define locus_h

#include "mpmtypes.h"
#include "ring.h"


/* GenParamStruct -- structure for specifying generation parameters */
/* .gen-param: This structure must match <code/mps.h#gen-param>. */

typedef struct GenParamStruct *GenParam;

typedef struct GenParamStruct {
  Size capacity;                /* capacity in kB */
  double mortality;             /* predicted mortality */
} GenParamStruct;


/* GenTrace -- per-generation per-trace structure */

typedef struct GenTraceStruct *GenTrace;

typedef struct GenTraceStruct {
  RingStruct traceRing;  /* link in ring of generations condemned by trace */
  Size condemned;        /* size of objects condemned by the trace */
  Size forwarded;        /* size of objects that were forwarded by the trace */
  Size preservedInPlace; /* size of objects preserved in place by the trace */
} GenTraceStruct;


/* GenDesc -- descriptor of a generation in a chain */

typedef struct GenDescStruct *GenDesc;

#define GenDescSig ((Sig)0x5199E4DE)  /* SIGnature GEN DEsc */

typedef struct GenDescStruct {
  Sig sig;              /* design.mps.sig.field */
  Serial serial;        /* serial number within arena */
  ZoneSet zones;        /* zoneset for this generation */
  Size capacity;        /* capacity in bytes */
  double mortality;     /* moving average mortality */
  RingStruct locusRing; /* Ring of all PoolGen's in this GenDesc (locus) */
  RingStruct segRing;   /* Ring of GCSegs in this generation */
  TraceSet activeTraces; /* set of traces collecting this generation */
  GenTraceStruct trace[TraceLIMIT];
} GenDescStruct;


/* PoolGen -- descriptor of a generation in a pool */

#define PoolGenSig ((Sig)0x519B009E)  /* SIGnature POOl GEn */

typedef struct PoolGenStruct {
  Sig sig;            /* design.mps.sig.field */
  Pool pool;          /* pool this belongs to */
  GenDesc gen;        /* generation this belongs to */
  /* link in ring of all PoolGen's in this GenDesc (locus) */
  RingStruct genRing;

  /* Accounting of memory in this generation for this pool */
  Size segs;              /* number of segments */
  Size totalSize;         /* total (sum of segment sizes) */
  Size freeSize;          /* unused (free or lost to fragmentation) */
  Size bufferedSize;      /* held in buffers but not condemned yet */
  Size newSize;           /* allocated since last collection */
  Size oldSize;           /* allocated prior to last collection */
  Size newDeferredSize;   /* new (but deferred) */
  Size oldDeferredSize;   /* old (but deferred) */
} PoolGenStruct;


/* Chain -- a generation chain */

#define ChainSig ((Sig)0x519C8A14)  /* SIGnature CHAIN */

typedef struct mps_chain_s {
  Sig sig;              /* design.mps.sig.field */
  Arena arena;
  RingStruct chainRing; /* list of chains in the arena */
  size_t genCount; /* number of generations */
  GenDesc gens; /* the array of generations */
} ChainStruct;


extern Bool GenDescCheck(GenDesc gen);
extern Size GenDescNewSize(GenDesc gen);
extern Size GenDescTotalSize(GenDesc gen);
extern void GenDescStartTrace(GenDesc gen, Trace trace);
extern void GenDescEndTrace(GenDesc gen, Trace trace);
extern void GenDescCondemned(GenDesc gen, Trace trace, Size size);
extern void GenDescSurvived(GenDesc gen, Trace trace, Size forwarded, Size preservedInPlace);
extern Res GenDescDescribe(GenDesc gen, mps_lib_FILE *stream, Count depth);
#define GenDescOfTraceRing(node, tr) PARENT(GenDescStruct, trace, RING_ELT(GenTrace, traceRing, node) - (tr)->ti)

extern Res ChainCreate(Chain *chainReturn, Arena arena, size_t genCount,
                       GenParam params);
extern void ChainDestroy(Chain chain);
extern Bool ChainCheck(Chain chain);

extern double ChainDeferral(Chain chain);
extern size_t ChainGens(Chain chain);
extern GenDesc ChainGen(Chain chain, Index gen);
extern Res ChainDescribe(Chain chain, mps_lib_FILE *stream, Count depth);

extern Bool PoolGenCheck(PoolGen pgen);
extern Res PoolGenInit(PoolGen pgen, GenDesc gen, Pool pool);
extern void PoolGenFinish(PoolGen pgen);
extern Res PoolGenAlloc(Seg *segReturn, PoolGen pgen, SegClass klass,
                        Size size, ArgList args);
extern void PoolGenFree(PoolGen pgen, Seg seg, Size freeSize, Size oldSize,
                        Size newSize, Bool deferred);
extern void PoolGenAccountForFill(PoolGen pgen, Size size);
extern void PoolGenAccountForEmpty(PoolGen pgen, Size used, Size unused, Bool deferred);
extern void PoolGenAccountForAge(PoolGen pgen, Size wasBuffered, Size wasNew, Bool deferred);
extern void PoolGenAccountForReclaim(PoolGen pgen, Size reclaimed, Bool deferred);
extern void PoolGenUndefer(PoolGen pgen, Size oldSize, Size newSize);
extern void PoolGenAccountForSegSplit(PoolGen pgen);
extern void PoolGenAccountForSegMerge(PoolGen pgen);
extern Res PoolGenDescribe(PoolGen gen, mps_lib_FILE *stream, Count depth);

#endif /* locus_h */


/* C. COPYRIGHT AND LICENSE
 *
 * Copyright (C) 2001-2020 Ravenbrook Limited <https://www.ravenbrook.com/>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
