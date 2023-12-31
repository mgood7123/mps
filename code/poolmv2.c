/* poolmv2.c: MANUAL VARIABLE-SIZED TEMPORAL POOL
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * .purpose: A manual-variable pool designed to take advantage of
 * placement according to predicted deathtime.
 *
 * .design: <design/poolmvt>.
 */

#include "mpm.h"
#include "poolmv2.h"
#include "mpscmvt.h"
#include "abq.h"
#include "cbs.h"
#include "failover.h"
#include "freelist.h"
#include "meter.h"
#include "range.h"

SRCID(poolmv2, "$Id$");


/* Signatures */

#define MVTSig ((Sig)0x5193F299) /* SIGnature MVT */


/* Private prototypes */

typedef struct MVTStruct *MVT;
static void MVTVarargs(ArgStruct args[MPS_ARGS_MAX], va_list varargs);
static Res MVTInit(Pool pool, Arena arena, PoolClass klass, ArgList arg);
static Bool MVTCheck(MVT mvt);
static void MVTFinish(Inst inst);
static Res MVTBufferFill(Addr *baseReturn, Addr *limitReturn,
                         Pool pool, Buffer buffer, Size minSize);
static void MVTBufferEmpty(Pool pool, Buffer buffer);
static void MVTFree(Pool pool, Addr base, Size size);
static Res MVTDescribe(Inst inst, mps_lib_FILE *stream, Count depth);
static Size MVTTotalSize(Pool pool);
static Size MVTFreeSize(Pool pool);
static Res MVTSegAlloc(Seg *segReturn, MVT mvt, Size size);

static void MVTSegFree(MVT mvt, Seg seg);
static Bool MVTReturnSegs(MVT mvt, Range range, Arena arena);
static Res MVTInsert(MVT mvt, Addr base, Addr limit);
static Res MVTDelete(MVT mvt, Addr base, Addr limit);
static void MVTRefillABQIfEmpty(MVT mvt, Size size);
static Res MVTContingencySearch(Addr *baseReturn, Addr *limitReturn,
                                MVT mvt, Size min);
static Bool MVTCheckFit(Addr base, Addr limit, Size min, Arena arena);
static ABQ MVTABQ(MVT mvt);
static Land MVTFreePrimary(MVT mvt);
static Land MVTFreeSecondary(MVT mvt);
static Land MVTFreeLand(MVT mvt);

typedef MVT MVTPool;
DECLARE_CLASS(Pool, MVTPool, AbstractBufferPool);


/* Types */

typedef struct MVTStruct
{
  PoolStruct poolStruct;
  CBSStruct cbsStruct;          /* The coalescing block structure */
  FreelistStruct flStruct;      /* The emergency free list structure */
  FailoverStruct foStruct;      /* The fail-over mechanism */
  ABQStruct abqStruct;          /* The available block queue */
  /* <design/poolmvt#.arch.parameters> */
  Size minSize;                 /* Pool parameter */
  Size meanSize;                /* Pool parameter */
  Size maxSize;                 /* Pool parameter */
  Count fragLimit;              /* Pool parameter */
  /* <design/poolmvt#.arch.overview.abq.reuse.size> */
  Size reuseSize;               /* Size at which blocks are recycled */
  /* <design/poolmvt#.arch.ap.fill.size> */
  Size fillSize;                /* Size of pool segments */
  /* <design/poolmvt#.arch.contingency> */
  Size availLimit;              /* Limit on available */
  /* <design/poolmvt#.impl.c.free.merge.segment.overflow> */
  Bool abqOverflow;             /* ABQ dropped some candidates */
  /* <design/poolmvt#.arch.ap.no-fit> */
  Bool splinter;                /* Saved splinter */
  Addr splinterBase;            /* Saved splinter base */
  Addr splinterLimit;           /* Saved splinter size */

  /* pool accounting --- one of these first four is redundant, but
     size and available are used to implement fragmentation policy */
  Size size;                    /* size of segs in pool */
  Size allocated;               /* bytes allocated to mutator */
  Size available;               /* bytes available for allocation */
  Size unavailable;             /* bytes lost to fragmentation */

  /* pool meters*/
  METER_DECL(segAllocs)
  METER_DECL(segFrees)
  METER_DECL(bufferFills)
  METER_DECL(bufferEmpties)
  METER_DECL(poolFrees)
  METER_DECL(poolSize)
  METER_DECL(poolAllocated)
  METER_DECL(poolAvailable)
  METER_DECL(poolUnavailable)
  METER_DECL(poolUtilization)
  /* abq meters */
  METER_DECL(finds)
  METER_DECL(overflows)
  METER_DECL(underflows)
  METER_DECL(refills)
  METER_DECL(refillPushes)
  METER_DECL(returns)
  /* fragmentation meters */
  METER_DECL(perfectFits)
  METER_DECL(firstFits)
  METER_DECL(secondFits)
  METER_DECL(failures)
  /* contingency meters */
  METER_DECL(emergencyContingencies)
  METER_DECL(fragLimitContingencies)
  METER_DECL(contingencySearches)
  METER_DECL(contingencyHardSearches)
  /* splinter meters */
  METER_DECL(splinters)
  METER_DECL(splintersUsed)
  METER_DECL(splintersDropped)
  METER_DECL(sawdust)
  /* exception meters */
  METER_DECL(exceptions)
  METER_DECL(exceptionSplinters)
  METER_DECL(exceptionReturns)

  Sig sig; /* design.mps.sig.field.end.outer */
} MVTStruct;


DEFINE_CLASS(Pool, MVTPool, klass)
{
  INHERIT_CLASS(klass, MVTPool, AbstractBufferPool);
  klass->instClassStruct.describe = MVTDescribe;
  klass->instClassStruct.finish = MVTFinish;
  klass->size = sizeof(MVTStruct);
  klass->varargs = MVTVarargs;
  klass->init = MVTInit;
  klass->free = MVTFree;
  klass->bufferFill = MVTBufferFill;
  klass->bufferEmpty = MVTBufferEmpty;
  klass->totalSize = MVTTotalSize;
  klass->freeSize = MVTFreeSize;
  AVERT(PoolClass, klass);
}

/* Macros */

#define PoolMVT(pool) PARENT(MVTStruct, poolStruct, pool)
#define MVTPool(mvt) (&(mvt)->poolStruct)


/* Accessors */


static ABQ MVTABQ(MVT mvt)
{
  return &mvt->abqStruct;
}


static Land MVTFreePrimary(MVT mvt)
{
  return CBSLand(&mvt->cbsStruct);
}


static Land MVTFreeSecondary(MVT mvt)
{
  return FreelistLand(&mvt->flStruct);
}


static Land MVTFreeLand(MVT mvt)
{
  return FailoverLand(&mvt->foStruct);
}


/* Methods */


/* MVTVarargs -- decode obsolete varargs */

static void MVTVarargs(ArgStruct args[MPS_ARGS_MAX], va_list varargs)
{
  args[0].key = MPS_KEY_MIN_SIZE;
  args[0].val.size = va_arg(varargs, Size);
  args[1].key = MPS_KEY_MEAN_SIZE;
  args[1].val.size = va_arg(varargs, Size);
  args[2].key = MPS_KEY_MAX_SIZE;
  args[2].val.size = va_arg(varargs, Size);
  args[3].key = MPS_KEY_MVT_RESERVE_DEPTH;
  args[3].val.count = va_arg(varargs, Count);
  /* Divide the old "percentage" argument by 100, fixing job003319. */
  args[4].key = MPS_KEY_MVT_FRAG_LIMIT;
  args[4].val.d = (double)va_arg(varargs, Count) / 100.0;
  args[5].key = MPS_KEY_ARGS_END;
  AVERT(ArgList, args);
}


/* MVTInit -- initialize an MVT pool
 *
 * Parameters are:
 * minSize, meanSize, maxSize, reserveDepth, fragLimit
 */

ARG_DEFINE_KEY(MVT_MIN_SIZE, Size);
ARG_DEFINE_KEY(MVT_MEAN_SIZE, Size);
ARG_DEFINE_KEY(MVT_MAX_SIZE, Size);
ARG_DEFINE_KEY(MVT_RESERVE_DEPTH, Count);
ARG_DEFINE_KEY(MVT_FRAG_LIMIT, double);

static Res MVTInit(Pool pool, Arena arena, PoolClass klass, ArgList args)
{
  Size align = MVT_ALIGN_DEFAULT;
  Size minSize = MVT_MIN_SIZE_DEFAULT;
  Size meanSize = MVT_MEAN_SIZE_DEFAULT;
  Size maxSize = MVT_MAX_SIZE_DEFAULT;
  Count reserveDepth = MVT_RESERVE_DEPTH_DEFAULT;
  Count fragLimit = MVT_FRAG_LIMIT_DEFAULT;
  Size reuseSize, fillSize;
  Count abqDepth;
  MVT mvt;
  Res res;
  ArgStruct arg;

  AVER(pool != NULL);
  AVERT(Arena, arena);
  AVERT(ArgList, args);
  UNUSED(klass); /* used for debug pools only */

  if (ArgPick(&arg, args, MPS_KEY_ALIGN))
    align = arg.val.align;
  if (ArgPick(&arg, args, MPS_KEY_MIN_SIZE))
    minSize = arg.val.size;
  if (ArgPick(&arg, args, MPS_KEY_MEAN_SIZE))
    meanSize = arg.val.size;
  if (ArgPick(&arg, args, MPS_KEY_MAX_SIZE))
    maxSize = arg.val.size;
  if (ArgPick(&arg, args, MPS_KEY_MVT_RESERVE_DEPTH))
    reserveDepth = arg.val.count;
  if (ArgPick(&arg, args, MPS_KEY_MVT_FRAG_LIMIT)) {
    /* pending complete fix for job003319 */
    AVER(0 <= arg.val.d);
    AVER(arg.val.d <= 1);
    fragLimit = (Count)(arg.val.d * 100);
  }

  AVERT(Align, align);
  /* This restriction on the alignment is necessary because of the use
     of a Freelist to store the free address ranges in low-memory
     situations. <design/freelist#.impl.grain.align>. */
  AVER(AlignIsAligned(align, FreelistMinimumAlignment));
  AVER(align <= ArenaGrainSize(arena));
  AVER(0 < minSize);
  AVER(minSize <= meanSize);
  AVER(meanSize <= maxSize);
  AVER(reserveDepth > 0);
  AVER(fragLimit <= 100);
  /* TODO: More parameter checks possible? */

  /* see <design/poolmvt#.arch.parameters> */
  fillSize = SizeArenaGrains(maxSize, arena);
  /* see <design/poolmvt#.arch.fragmentation.internal> */
  reuseSize = 2 * fillSize;
  abqDepth = (reserveDepth * meanSize + reuseSize - 1) / reuseSize;
  /* keep the abq from being useless */
  if (abqDepth < 3)
    abqDepth = 3;

  res = NextMethod(Pool, MVTPool, init)(pool, arena, klass, args);
  if (res != ResOK)
    goto failNextInit;
  mvt = CouldBeA(MVTPool, pool);

  res = LandInit(MVTFreePrimary(mvt), CLASS(CBSFast), arena, align, mvt,
                 mps_args_none);
  if (res != ResOK)
    goto failFreePrimaryInit;

  res = LandInit(MVTFreeSecondary(mvt), CLASS(Freelist), arena, align,
                 mvt, mps_args_none);
  if (res != ResOK)
    goto failFreeSecondaryInit;

  MPS_ARGS_BEGIN(foArgs) {
    MPS_ARGS_ADD(foArgs, FailoverPrimary, MVTFreePrimary(mvt));
    MPS_ARGS_ADD(foArgs, FailoverSecondary, MVTFreeSecondary(mvt));
    res = LandInit(MVTFreeLand(mvt), CLASS(Failover), arena, align, mvt,
                   foArgs);
  } MPS_ARGS_END(foArgs);
  if (res != ResOK)
    goto failFreeLandInit;

  res = ABQInit(arena, MVTABQ(mvt), (void *)mvt, abqDepth, sizeof(RangeStruct));
  if (res != ResOK)
    goto failABQInit;

  pool->alignment = align;
  pool->alignShift = SizeLog2(pool->alignment);
  mvt->reuseSize = reuseSize;
  mvt->fillSize = fillSize;
  mvt->abqOverflow = FALSE;
  mvt->minSize = minSize;
  mvt->meanSize = meanSize;
  mvt->maxSize = maxSize;
  mvt->fragLimit = fragLimit;
  mvt->splinter = FALSE;
  mvt->splinterBase = (Addr)0;
  mvt->splinterLimit = (Addr)0;

  /* accounting */
  mvt->size = 0;
  mvt->allocated = 0;
  mvt->available = 0;
  mvt->availLimit = 0;
  mvt->unavailable = 0;

  /* meters*/
  METER_INIT(mvt->segAllocs, "segment allocations", (void *)mvt);
  METER_INIT(mvt->segFrees, "segment frees", (void *)mvt);
  METER_INIT(mvt->bufferFills, "buffer fills", (void *)mvt);
  METER_INIT(mvt->bufferEmpties, "buffer empties", (void *)mvt);
  METER_INIT(mvt->poolFrees, "pool frees", (void *)mvt);
  METER_INIT(mvt->poolSize, "pool size", (void *)mvt);
  METER_INIT(mvt->poolAllocated, "pool allocated", (void *)mvt);
  METER_INIT(mvt->poolAvailable, "pool available", (void *)mvt);
  METER_INIT(mvt->poolUnavailable, "pool unavailable", (void *)mvt);
  METER_INIT(mvt->poolUtilization, "pool utilization", (void *)mvt);
  METER_INIT(mvt->finds, "ABQ finds", (void *)mvt);
  METER_INIT(mvt->overflows, "ABQ overflows", (void *)mvt);
  METER_INIT(mvt->underflows, "ABQ underflows", (void *)mvt);
  METER_INIT(mvt->refills, "ABQ refills", (void *)mvt);
  METER_INIT(mvt->refillPushes, "ABQ refill pushes", (void *)mvt);
  METER_INIT(mvt->returns, "ABQ returns", (void *)mvt);
  METER_INIT(mvt->perfectFits, "perfect fits", (void *)mvt);
  METER_INIT(mvt->firstFits, "first fits", (void *)mvt);
  METER_INIT(mvt->secondFits, "second fits", (void *)mvt);
  METER_INIT(mvt->failures, "failures", (void *)mvt);
  METER_INIT(mvt->emergencyContingencies, "emergency contingencies",
             (void *)mvt);
  METER_INIT(mvt->fragLimitContingencies,
             "fragmentation limit contingencies", (void *)mvt);
  METER_INIT(mvt->contingencySearches, "contingency searches", (void *)mvt);
  METER_INIT(mvt->contingencyHardSearches,
             "contingency hard searches", (void *)mvt);
  METER_INIT(mvt->splinters, "splinters", (void *)mvt);
  METER_INIT(mvt->splintersUsed, "splinters used", (void *)mvt);
  METER_INIT(mvt->splintersDropped, "splinters dropped", (void *)mvt);
  METER_INIT(mvt->sawdust, "sawdust", (void *)mvt);
  METER_INIT(mvt->exceptions, "exceptions", (void *)mvt);
  METER_INIT(mvt->exceptionSplinters, "exception splinters", (void *)mvt);
  METER_INIT(mvt->exceptionReturns, "exception returns", (void *)mvt);

  SetClassOfPoly(pool, CLASS(MVTPool));
  mvt->sig = MVTSig;
  AVERC(MVT, mvt);

  EVENT6(PoolInitMVT, pool, minSize, meanSize, maxSize,
               reserveDepth, fragLimit);

  return ResOK;

failABQInit:
  LandFinish(MVTFreeLand(mvt));
failFreeLandInit:
  LandFinish(MVTFreeSecondary(mvt));
failFreeSecondaryInit:
  LandFinish(MVTFreePrimary(mvt));
failFreePrimaryInit:
  NextMethod(Inst, MVTPool, finish)(MustBeA(Inst, pool));
failNextInit:
  AVER(res != ResOK);
  return res;
}


/* MVTCheck -- validate an MVT Pool */

ATTRIBUTE_UNUSED
static Bool MVTCheck(MVT mvt)
{
  CHECKS(MVT, mvt);
  CHECKC(MVTPool, mvt);
  CHECKD(Pool, MVTPool(mvt));
  CHECKC(MVTPool, mvt);
  CHECKD(CBS, &mvt->cbsStruct);
  CHECKD(ABQ, &mvt->abqStruct);
  CHECKD(Freelist, &mvt->flStruct);
  CHECKD(Failover, &mvt->foStruct);
  CHECKL(mvt->reuseSize >= 2 * mvt->fillSize);
  CHECKL(mvt->fillSize >= mvt->maxSize);
  CHECKL(mvt->maxSize >= mvt->meanSize);
  CHECKL(mvt->meanSize >= mvt->minSize);
  CHECKL(mvt->minSize > 0);
  CHECKL(mvt->fragLimit <= 100);
  CHECKL(mvt->availLimit == mvt->size * mvt->fragLimit / 100);
  CHECKL(BoolCheck(mvt->abqOverflow));
  CHECKL(BoolCheck(mvt->splinter));
  if (mvt->splinter) {
    CHECKL(AddrOffset(mvt->splinterBase, mvt->splinterLimit) >=
           mvt->minSize);
    CHECKL(mvt->splinterBase < mvt->splinterLimit);
  }
  CHECKL(mvt->size == mvt->allocated + mvt->available +
         mvt->unavailable);
  /* --- could check that sum of segment sizes == mvt->size */
  /* --- check meters? */

  return TRUE;
}


/* MVTFinish -- finish an MVT pool
 */
static void MVTFinish(Inst inst)
{
  Pool pool = MustBeA(AbstractPool, inst);
  MVT mvt = MustBeA(MVTPool, pool);
  Arena arena = PoolArena(pool);
  Ring ring;
  Ring node, nextNode;

  AVERT(MVT, mvt);

  mvt->sig = SigInvalid;

  /* Free the segments in the pool */
  ring = PoolSegRing(pool);
  RING_FOR(node, ring, nextNode) {
    /* We mustn't call MVTSegFree, because we don't know whether or not
     * there was any fragmented (unavailable) space in this segment,
     * and so we can't keep the accounting correct. */
    SegFree(SegOfPoolRing(node));
  }

  /* Finish the ABQ, Failover, Freelist and CBS structures */
  ABQFinish(arena, MVTABQ(mvt));
  LandFinish(MVTFreeLand(mvt));
  LandFinish(MVTFreeSecondary(mvt));
  LandFinish(MVTFreePrimary(mvt));

  NextMethod(Inst, MVTPool, finish)(inst);
}


/* SURELY(expr) -- evaluate expr and AVER that the result is true */

#define SURELY(expr) \
  BEGIN \
    Bool _b = (expr); \
    AVER(_b); \
    UNUSED(_b); \
  END


/* MUST(expr) -- evaluate expr and AVER that the result is ResOK */

#define MUST(expr) \
  BEGIN \
    Res _res = (expr); \
    AVER(_res == ResOK); \
    UNUSED(_res); \
  END


/* MVTNoteFill -- record that a buffer fill has occurred */

static void MVTNoteFill(MVT mvt, Addr base, Addr limit, Size minSize)
{
  mvt->available -= AddrOffset(base, limit);
  mvt->allocated += AddrOffset(base, limit);
  AVER(mvt->size == mvt->allocated + mvt->available + mvt->unavailable);
  METER_ACC(mvt->poolUtilization, mvt->allocated * 100 / mvt->size);
  METER_ACC(mvt->poolUnavailable, mvt->unavailable);
  METER_ACC(mvt->poolAvailable, mvt->available);
  METER_ACC(mvt->poolAllocated, mvt->allocated);
  METER_ACC(mvt->poolSize, mvt->size);
  METER_ACC(mvt->bufferFills, AddrOffset(base, limit));
  AVER(AddrOffset(base, limit) >= minSize);
}


/* MVTOversizeFill -- try to fill a request for a large object
 *
 * When a request exceeds mvt->fillSize, we allocate it on a segment of
 * its own.
 */
static Res MVTOversizeFill(Addr *baseReturn,
                           Addr *limitReturn,
                           MVT mvt,
                           Size minSize)
{
  Res res;
  Seg seg;
  Addr base, limit;
  Size alignedSize;

  alignedSize = SizeArenaGrains(minSize, PoolArena(MVTPool(mvt)));

  res = MVTSegAlloc(&seg, mvt, alignedSize);
  if (res != ResOK)
    return res;

  /* Just exactly fill the buffer so that only this allocation comes from
     the segment. */
  base = SegBase(seg);
  limit = AddrAdd(SegBase(seg), minSize);

  /* The rest of the segment was lost to fragmentation, so transfer it
   * to the unavailable total. (We deliberately lose these fragments
   * now so as to avoid the more severe fragmentation that we believe
   * would result if we used these for allocation. See
   * <design/poolmvt#.arch.fragmentation.internal> and
   * <design/poolmvt#.analysis.policy.size>.)
   */
  mvt->available -= alignedSize - minSize;
  mvt->unavailable += alignedSize - minSize;

  METER_ACC(mvt->exceptions, minSize);
  METER_ACC(mvt->exceptionSplinters, alignedSize - minSize);

  MVTNoteFill(mvt, base, limit, minSize);
  *baseReturn = base;
  *limitReturn = limit;
  return ResOK;
}


/* MVTSplinterFill -- try to fill a request from the splinter */

static Bool MVTSplinterFill(Addr *baseReturn, Addr *limitReturn,
                            MVT mvt, Size minSize)
{
  Addr base, limit;

  if (!mvt->splinter ||
      AddrOffset(mvt->splinterBase, mvt->splinterLimit) < minSize)
    return FALSE;

  base = mvt->splinterBase;
  limit = mvt->splinterLimit;
  mvt->splinter = FALSE;

  METER_ACC(mvt->splintersUsed, AddrOffset(base, limit));

  MVTNoteFill(mvt, base, limit, minSize);
  *baseReturn = base;
  *limitReturn = limit;
  return TRUE;
}


/* MVTOneSegOnly -- restrict a buffer fill to a single segment
 *
 * After a block has been found, this is applied so that the block
 * used to fill the buffer does not span multiple segments. (This
 * makes it more likely that when we free the objects that were
 * allocated from the block, that this will free the whole segment,
 * and so we'll be able to return the segment to the arena. A block
 * that spanned two segments would keep both segments allocated,
 * possibly unnecessarily.)
 */
static void MVTOneSegOnly(Addr *baseIO, Addr *limitIO, MVT mvt, Size minSize)
{
  Addr base, limit, segLimit;
  Seg seg = NULL;           /* suppress "may be used uninitialized" */
  Arena arena;

  base = *baseIO;
  limit = *limitIO;

  arena = PoolArena(MVTPool(mvt));

  SURELY(SegOfAddr(&seg, arena, base));
  segLimit = SegLimit(seg);
  if (limit <= segLimit) {
    /* perfect fit */
    METER_ACC(mvt->perfectFits, AddrOffset(base, limit));
  } else if (AddrOffset(base, segLimit) >= minSize) {
    /* fit in 1st segment */
    limit = segLimit;
    METER_ACC(mvt->firstFits, AddrOffset(base, limit));
  } else {
    /* fit in 2nd segment */
    base = segLimit;
    SURELY(SegOfAddr(&seg, arena, base));
    segLimit = SegLimit(seg);
    if (limit > segLimit)
      limit = segLimit;
    METER_ACC(mvt->secondFits, AddrOffset(base, limit));
  }

  *baseIO = base;
  *limitIO = limit;
}


/* MVTABQFill -- try to fill a request from the available block queue */

static Bool MVTABQFill(Addr *baseReturn, Addr *limitReturn,
                       MVT mvt, Size minSize)
{
  Addr base, limit;
  RangeStruct range;
  Res res;

  MVTRefillABQIfEmpty(mvt, minSize);

  if (!ABQPeek(MVTABQ(mvt), &range))
    return FALSE;
  /* Check that the range was stored and retrieved correctly by the ABQ. */
  AVERT(Range, &range);

  base = RangeBase(&range);
  limit = RangeLimit(&range);
  MVTOneSegOnly(&base, &limit, mvt, minSize);

  METER_ACC(mvt->finds, minSize);

  res = MVTDelete(mvt, base, limit);
  if (res != ResOK) {
    return FALSE;
  }

  MVTNoteFill(mvt, base, limit, minSize);
  *baseReturn = base;
  *limitReturn = limit;
  return TRUE;
}


/* MVTContingencyFill -- try to fill a request from the free lists */
static Bool MVTContingencyFill(Addr *baseReturn, Addr *limitReturn,
                               MVT mvt, Size minSize)
{
  Res res;
  Addr base, limit;

  if (!MVTContingencySearch(&base, &limit, mvt, minSize))
    return FALSE;

  MVTOneSegOnly(&base, &limit, mvt, minSize);

  res = MVTDelete(mvt, base, limit);
  if (res != ResOK)
    return FALSE;

  MVTNoteFill(mvt, base, limit, minSize);
  *baseReturn = base;
  *limitReturn = limit;
  return TRUE;
}


/* MVTSegFill -- try to fill a request with a new segment */

static Res MVTSegFill(Addr *baseReturn, Addr *limitReturn,
                      MVT mvt, Size fillSize,
                      Size minSize)
{
  Res res;
  Seg seg;
  Addr base, limit;

  res = MVTSegAlloc(&seg, mvt, fillSize);
  if (res != ResOK)
    return res;

  base = SegBase(seg);
  limit = SegLimit(seg);

  MVTNoteFill(mvt, base, limit, minSize);
  *baseReturn = base;
  *limitReturn = limit;
  return ResOK;
}


/* MVTBufferFill -- refill an allocation buffer from an MVT pool
 *
 * <design/poolmvt#.impl.c.ap.fill>
 */
static Res MVTBufferFill(Addr *baseReturn, Addr *limitReturn,
                         Pool pool, Buffer buffer, Size minSize)
{
  MVT mvt;
  Res res;

  AVER(baseReturn != NULL);
  AVER(limitReturn != NULL);
  AVERT(Pool, pool);
  mvt = PoolMVT(pool);
  AVERT(MVT, mvt);
  AVERT(Buffer, buffer);
  AVER(BufferIsReset(buffer));
  AVER(minSize > 0);
  AVER(SizeIsAligned(minSize, pool->alignment));

  /* Allocate oversize blocks exactly, directly from the arena.
     <design/poolmvt#.arch.ap.no-fit.oversize> */
  if (minSize > mvt->fillSize) {
    return MVTOversizeFill(baseReturn, limitReturn, mvt,
                           minSize);
  }

  /* Use any splinter, if available.
     <design/poolmvt#.arch.ap.no-fit.return> */
  if (MVTSplinterFill(baseReturn, limitReturn, mvt, minSize))
    return ResOK;

  /* Attempt to retrieve a free block from the ABQ. */
  if (MVTABQFill(baseReturn, limitReturn, mvt, minSize))
    return ResOK;

  METER_ACC(mvt->underflows, minSize);

  /* If fragmentation is acceptable, attempt to find a free block from
     the free lists. <design/poolmvt#.arch.contingency.fragmentation-limit> */
  if (mvt->available >= mvt->availLimit) {
    METER_ACC(mvt->fragLimitContingencies, minSize);
    if (MVTContingencyFill(baseReturn, limitReturn, mvt, minSize))
      return ResOK;
  }

  /* Attempt to request a block from the arena.
     <design/poolmvt#.impl.c.free.merge.segment> */
  res = MVTSegFill(baseReturn, limitReturn,
                   mvt, mvt->fillSize, minSize);
  if (res == ResOK)
    return ResOK;

  /* Things are looking pretty desperate.  Try the contingencies again,
     disregarding fragmentation limits. */
  if (ResIsAllocFailure(res)) {
    METER_ACC(mvt->emergencyContingencies, minSize);
    if (MVTContingencyFill(baseReturn, limitReturn, mvt, minSize))
      return ResOK;
  }

  METER_ACC(mvt->failures, minSize);
  AVER(res != ResOK);
  return res;
}


/* MVTDeleteOverlapping -- ABQIterate callback used by MVTInsert and
 * MVTDelete. It receives a Range in its closure argument, and sets
 * *deleteReturn to TRUE for ranges in the ABQ that overlap with it,
 * and FALSE for ranges that do not.
 */
static Bool MVTDeleteOverlapping(Bool *deleteReturn, void *element,
                                 void *closure)
{
  Range oldRange, newRange;

  AVER(deleteReturn != NULL);
  AVER(element != NULL);
  AVER(closure != NULL);

  oldRange = element;
  newRange = closure;

  *deleteReturn = RangesOverlap(oldRange, newRange);
  return TRUE;
}


/* MVTReserve -- add a range to the available range queue, and if the
 * queue is full, return segments to the arena. Return TRUE if it
 * succeeded in adding the range to the queue, FALSE if the queue
 * overflowed.
 */
static Bool MVTReserve(MVT mvt, Range range)
{
  AVERT(MVT, mvt);
  AVERT(Range, range);
  AVER(RangeSize(range) >= mvt->reuseSize);

  /* <design/poolmvt#.impl.c.free.merge> */
  if (!ABQPush(MVTABQ(mvt), range)) {
    Arena arena = PoolArena(MVTPool(mvt));
    RangeStruct oldRange;
    /* We just failed to push, so the ABQ must be full, and so surely
     * the peek will succeed. */
    SURELY(ABQPeek(MVTABQ(mvt), &oldRange));
    AVERT(Range, &oldRange);
    if (!MVTReturnSegs(mvt, &oldRange, arena))
      goto overflow;
    METER_ACC(mvt->returns, RangeSize(&oldRange));
    if (!ABQPush(MVTABQ(mvt), range))
      goto overflow;
  }

  return TRUE;

overflow:
  mvt->abqOverflow = TRUE;
  METER_ACC(mvt->overflows, RangeSize(range));
  return FALSE;
}


/* MVTInsert -- insert an address range into the free lists and update
 * the ABQ accordingly.
 */
static Res MVTInsert(MVT mvt, Addr base, Addr limit)
{
  Res res;
  RangeStruct range, newRange;

  AVERT(MVT, mvt);
  AVER(base < limit);

  RangeInit(&range, base, limit);
  res = LandInsert(&newRange, MVTFreeLand(mvt), &range);
  if (res != ResOK)
    return res;

  if (RangeSize(&newRange) >= mvt->reuseSize) {
    /* The new range is big enough that it might have been coalesced
     * with ranges on the ABQ, so ensure that the corresponding ranges
     * are coalesced on the ABQ.
     */
    ABQIterate(MVTABQ(mvt), MVTDeleteOverlapping, &newRange);
    (void)MVTReserve(mvt, &newRange);
  }

  return ResOK;
}


/* MVTDelete -- delete an address range from the free lists, and
 * update the ABQ accordingly.
 */
static Res MVTDelete(MVT mvt, Addr base, Addr limit)
{
  RangeStruct range, rangeOld, rangeLeft, rangeRight;
  Res res;

  AVERT(MVT, mvt);
  AVER(base < limit);

  RangeInit(&range, base, limit);
  res = LandDelete(&rangeOld, MVTFreeLand(mvt), &range);
  if (res != ResOK)
    return res;
  AVER(RangesNest(&rangeOld, &range));

  /* If the old address range was larger than the reuse size, then it
   * might be on the ABQ, so ensure it is removed.
   */
  if (RangeSize(&rangeOld) >= mvt->reuseSize)
    ABQIterate(MVTABQ(mvt), MVTDeleteOverlapping, &rangeOld);

  /* There might be fragments at the left or the right of the deleted
   * range, and either might be big enough to go back on the ABQ.
   */
  RangeInit(&rangeLeft, RangeBase(&rangeOld), base);
  if (RangeSize(&rangeLeft) >= mvt->reuseSize)
    (void)MVTReserve(mvt, &rangeLeft);

  RangeInit(&rangeRight, limit, RangeLimit(&rangeOld));
  if (RangeSize(&rangeRight) >= mvt->reuseSize)
    (void)MVTReserve(mvt, &rangeRight);

  return ResOK;
}


/* MVTBufferEmpty -- return an unusable portion of a buffer to the MVT
 * pool
 *
 * <design/poolmvt#.impl.c.ap.empty>
 */
static void MVTBufferEmpty(Pool pool, Buffer buffer)
{
  MVT mvt;
  Size size;
  Res res;
  Addr base, limit;

  AVERT(Pool, pool);
  mvt = PoolMVT(pool);
  AVERT(MVT, mvt);
  AVERT(Buffer, buffer);
  AVER(BufferIsReady(buffer));
  base = BufferGetInit(buffer);
  limit = BufferLimit(buffer);
  AVER(base <= limit);

  size = AddrOffset(base, limit);
  if (size == 0)
    return;

  mvt->available += size;
  mvt->allocated -= size;
  AVER(mvt->size == mvt->allocated + mvt->available +
       mvt->unavailable);
  METER_ACC(mvt->poolUtilization, mvt->allocated * 100 / mvt->size);
  METER_ACC(mvt->poolUnavailable, mvt->unavailable);
  METER_ACC(mvt->poolAvailable, mvt->available);
  METER_ACC(mvt->poolAllocated, mvt->allocated);
  METER_ACC(mvt->poolSize, mvt->size);
  METER_ACC(mvt->bufferEmpties, size);

  /* <design/poolmvt#.arch.ap.no-fit.splinter> */
  if (size < mvt->minSize) {
    res = MVTInsert(mvt, base, limit);
    AVER(res == ResOK);
    METER_ACC(mvt->sawdust, size);
    return;
  }

  METER_ACC(mvt->splinters, size);
  /* <design/poolmvt#.arch.ap.no-fit.return> */
  if (mvt->splinter) {
    Size oldSize = AddrOffset(mvt->splinterBase, mvt->splinterLimit);

    /* Old better, drop new */
    if (size < oldSize) {
      res = MVTInsert(mvt, base, limit);
      AVER(res == ResOK);
      METER_ACC(mvt->splintersDropped, size);
      return;
    } else {
      /* New better, drop old */
      res = MVTInsert(mvt, mvt->splinterBase, mvt->splinterLimit);
      AVER(res == ResOK);
      METER_ACC(mvt->splintersDropped, oldSize);
    }
  }

  mvt->splinter = TRUE;
  mvt->splinterBase = base;
  mvt->splinterLimit = limit;
}


/* MVTFree -- free a block (previously allocated from a buffer) that
 * is no longer in use
 *
 * see <design/poolmvt#.impl.c.free>
 */
static void MVTFree(Pool pool, Addr base, Size size)
{
  MVT mvt;
  Addr limit;

  AVERT(Pool, pool);
  mvt = PoolMVT(pool);
  AVERT(MVT, mvt);
  AVER(base != (Addr)0);
  AVER(size > 0);

  /* We know the buffer observes pool->alignment  */
  size = SizeAlignUp(size, pool->alignment);
  limit = AddrAdd(base, size);
  METER_ACC(mvt->poolFrees, size);
  mvt->available += size;
  mvt->allocated -= size;
  AVER(mvt->size == mvt->allocated + mvt->available + mvt->unavailable);
  METER_ACC(mvt->poolUtilization, mvt->allocated * 100 / mvt->size);
  METER_ACC(mvt->poolUnavailable, mvt->unavailable);
  METER_ACC(mvt->poolAvailable, mvt->available);
  METER_ACC(mvt->poolAllocated, mvt->allocated);
  METER_ACC(mvt->poolSize, mvt->size);

  /* <design/poolmvt#.arch.ap.no-fit.oversize.policy> */
  /* Return exceptional blocks directly to arena */
  if (size > mvt->fillSize) {
    Seg seg = NULL;         /* suppress "may be used uninitialized" */
    SURELY(SegOfAddr(&seg, PoolArena(pool), base));
    AVER(base == SegBase(seg));
    AVER(limit <= SegLimit(seg));
    mvt->available += SegSize(seg) - size;
    mvt->unavailable -= SegSize(seg) - size;
    AVER(mvt->size == mvt->allocated + mvt->available +
         mvt->unavailable);
    METER_ACC(mvt->exceptionReturns, SegSize(seg));
    MVTSegFree(mvt, seg);
    return;
  }

  MUST(MVTInsert(mvt, base, limit));
}


/* MVTTotalSize -- total memory allocated from the arena */

static Size MVTTotalSize(Pool pool)
{
  MVT mvt;

  AVERT(Pool, pool);
  mvt = PoolMVT(pool);
  AVERT(MVT, mvt);

  return mvt->size;
}


/* MVTFreeSize -- free memory (unused by client program) */

static Size MVTFreeSize(Pool pool)
{
  MVT mvt;

  AVERT(Pool, pool);
  mvt = PoolMVT(pool);
  AVERT(MVT, mvt);

  return mvt->available + mvt->unavailable;
}


/* MVTDescribe -- describe an MVT pool */

static Res MVTDescribe(Inst inst, mps_lib_FILE *stream, Count depth)
{
  Pool pool = CouldBeA(AbstractPool, inst);
  MVT mvt = CouldBeA(MVTPool, pool);
  Res res;

  if (!TESTC(MVTPool, mvt))
    return ResPARAM;
  if (stream == NULL)
    return ResPARAM;

  res = NextMethod(Inst, MVTPool, describe)(inst, stream, depth);
  if (res != ResOK)
    return res;

  res = WriteF(stream, depth + 2,
               "minSize: $U\n", (WriteFU)mvt->minSize,
               "meanSize: $U\n", (WriteFU)mvt->meanSize,
               "maxSize: $U\n", (WriteFU)mvt->maxSize,
               "fragLimit: $U\n", (WriteFU)mvt->fragLimit,
               "reuseSize: $U\n", (WriteFU)mvt->reuseSize,
               "fillSize: $U\n", (WriteFU)mvt->fillSize,
               "availLimit: $U\n", (WriteFU)mvt->availLimit,
               "abqOverflow: $S\n", WriteFYesNo(mvt->abqOverflow),
               "splinter: $S\n", WriteFYesNo(mvt->splinter),
               "splinterBase: $A\n", (WriteFA)mvt->splinterBase,
               "splinterLimit: $A\n", (WriteFU)mvt->splinterLimit,
               "size: $U\n", (WriteFU)mvt->size,
               "allocated: $U\n", (WriteFU)mvt->allocated,
               "available: $U\n", (WriteFU)mvt->available,
               "unavailable: $U\n", (WriteFU)mvt->unavailable,
               NULL);
  if (res != ResOK)
    return res;

  res = LandDescribe(MVTFreePrimary(mvt), stream, depth + 2);
  if (res != ResOK)
    return res;
  res = LandDescribe(MVTFreeSecondary(mvt), stream, depth + 2);
  if (res != ResOK)
    return res;
  res = LandDescribe(MVTFreeLand(mvt), stream, depth + 2);
  if (res != ResOK)
    return res;
  res = ABQDescribe(MVTABQ(mvt), (ABQDescribeElement)RangeDescribe, stream,
                    depth + 2);
  if (res != ResOK)
    return res;

  METER_WRITE(mvt->segAllocs, stream, depth + 2);
  METER_WRITE(mvt->segFrees, stream, depth + 2);
  METER_WRITE(mvt->bufferFills, stream, depth + 2);
  METER_WRITE(mvt->bufferEmpties, stream, depth + 2);
  METER_WRITE(mvt->poolFrees, stream, depth + 2);
  METER_WRITE(mvt->poolSize, stream, depth + 2);
  METER_WRITE(mvt->poolAllocated, stream, depth + 2);
  METER_WRITE(mvt->poolAvailable, stream, depth + 2);
  METER_WRITE(mvt->poolUnavailable, stream, depth + 2);
  METER_WRITE(mvt->poolUtilization, stream, depth + 2);
  METER_WRITE(mvt->finds, stream, depth + 2);
  METER_WRITE(mvt->overflows, stream, depth + 2);
  METER_WRITE(mvt->underflows, stream, depth + 2);
  METER_WRITE(mvt->refills, stream, depth + 2);
  METER_WRITE(mvt->refillPushes, stream, depth + 2);
  METER_WRITE(mvt->returns, stream, depth + 2);
  METER_WRITE(mvt->perfectFits, stream, depth + 2);
  METER_WRITE(mvt->firstFits, stream, depth + 2);
  METER_WRITE(mvt->secondFits, stream, depth + 2);
  METER_WRITE(mvt->failures, stream, depth + 2);
  METER_WRITE(mvt->emergencyContingencies, stream, depth + 2);
  METER_WRITE(mvt->fragLimitContingencies, stream, depth + 2);
  METER_WRITE(mvt->contingencySearches, stream, depth + 2);
  METER_WRITE(mvt->contingencyHardSearches, stream, depth + 2);
  METER_WRITE(mvt->splinters, stream, depth + 2);
  METER_WRITE(mvt->splintersUsed, stream, depth + 2);
  METER_WRITE(mvt->splintersDropped, stream, depth + 2);
  METER_WRITE(mvt->sawdust, stream, depth + 2);
  METER_WRITE(mvt->exceptions, stream, depth + 2);
  METER_WRITE(mvt->exceptionSplinters, stream, depth + 2);
  METER_WRITE(mvt->exceptionReturns, stream, depth + 2);

  return ResOK;
}


/* Pool Interface */


/* PoolClassMVT -- the Pool (sub-)Class for an MVT pool */

PoolClass PoolClassMVT(void)
{
  return CLASS(MVTPool);
}


/* MPS Interface */


/* mps_class_mvt -- the class of an mvt pool */

mps_pool_class_t mps_class_mvt(void)
{
  return (mps_pool_class_t)(PoolClassMVT());
}


/* Internal methods */


/* MVTSegAlloc -- encapsulates SegAlloc with associated accounting and
 * metering
 */
static Res MVTSegAlloc(Seg *segReturn, MVT mvt, Size size)
{
  Res res = SegAlloc(segReturn, CLASS(Seg), LocusPrefDefault(), size,
                     MVTPool(mvt), argsNone);

  if (res == ResOK) {
    Size segSize = SegSize(*segReturn);

    /* see <design/poolmvt#.arch.fragmentation.internal> */
    AVER(segSize >= mvt->fillSize);
    mvt->size += segSize;
    mvt->available += segSize;
    mvt->availLimit = mvt->size * mvt->fragLimit / 100;
    AVER(mvt->size == mvt->allocated + mvt->available + mvt->unavailable);
    METER_ACC(mvt->segAllocs, segSize);
  }
  return res;
}


/* MVTSegFree -- encapsulates SegFree with associated accounting and
 * metering
 */
static void MVTSegFree(MVT mvt, Seg seg)
{
  Size size;

  size = SegSize(seg);
  AVER(mvt->available >= size);

  mvt->available -= size;
  mvt->size -= size;
  mvt->availLimit = mvt->size * mvt->fragLimit / 100;
  AVER(mvt->size == mvt->allocated + mvt->available + mvt->unavailable);

  SegFree(seg);
  METER_ACC(mvt->segFrees, size);
}


/* MVTReturnSegs -- return (interior) segments of a range to the arena */

static Bool MVTReturnSegs(MVT mvt, Range range, Arena arena)
{
  Addr base, limit;
  Bool success = FALSE;

  base = RangeBase(range);
  limit = RangeLimit(range);

  while (base < limit) {
    Seg seg = NULL;         /* suppress "may be used uninitialized" */
    Addr segBase, segLimit;

    SURELY(SegOfAddr(&seg, arena, base));
    segBase = SegBase(seg);
    segLimit = SegLimit(seg);
    if (base <= segBase && limit >= segLimit) {
      MUST(MVTDelete(mvt, segBase, segLimit));
      MVTSegFree(mvt, seg);
      success = TRUE;
    }
    base = segLimit;
  }

  return success;
}


/* MVTRefillABQIfEmpty -- refill the ABQ from the free lists if it is
 * empty.
 */

static Bool MVTRefillVisitor(Land land, Range range,
                             void *closure)
{
  MVT mvt;

  AVERT(Land, land);
  mvt = closure;
  AVERT(MVT, mvt);

  if (RangeSize(range) < mvt->reuseSize)
    return TRUE;

  METER_ACC(mvt->refillPushes, ABQDepth(MVTABQ(mvt)));
  return MVTReserve(mvt, range);
}

static void MVTRefillABQIfEmpty(MVT mvt, Size size)
{
  AVERT(MVT, mvt);
  AVER(size > 0);

  /* If there have never been any overflows from the ABQ back to the
   * free lists, then there cannot be any blocks in the free lists
   * that are worth adding to the ABQ. So as an optimization, we don't
   * bother to look.
   */
  if (mvt->abqOverflow && ABQIsEmpty(MVTABQ(mvt))) {
    mvt->abqOverflow = FALSE;
    METER_ACC(mvt->refills, size);
    /* The iteration stops if the ABQ overflows, so may finish or not. */
    (void)LandIterate(MVTFreeLand(mvt), MVTRefillVisitor, mvt);
  }
}


/* MVTContingencySearch -- search free lists for a block of a given size */

typedef struct MVTContigencyClosureStruct
{
  MVT mvt;
  RangeStruct range;
  Arena arena;
  Size min;
  /* meters */
  Count steps;
  Count hardSteps;
} MVTContigencyClosureStruct,  *MVTContigencyClosure;

static Bool MVTContingencyVisitor(Land land, Range range,
                                  void *closure)
{
  MVT mvt;
  Size size;
  Addr base, limit;
  MVTContigencyClosure cl;

  AVERT(Land, land);
  AVERT(Range, range);
  AVER(closure != NULL);
  cl = closure;
  mvt = cl->mvt;
  AVERT(MVT, mvt);

  base = RangeBase(range);
  limit = RangeLimit(range);
  size = RangeSize(range);

  cl->steps++;
  if (size < cl->min)
    return TRUE;

  /* verify that min will fit when seg-aligned */
  if (size >= 2 * cl->min) {
    RangeInit(&cl->range, base, limit);
    return FALSE;
  }

  /* do it the hard way */
  cl->hardSteps++;
  if (MVTCheckFit(base, limit, cl->min, cl->arena)) {
    RangeInit(&cl->range, base, limit);
    return FALSE;
  }

  /* keep looking */
  return TRUE;
}

static Bool MVTContingencySearch(Addr *baseReturn, Addr *limitReturn,
                                 MVT mvt, Size min)
{
  MVTContigencyClosureStruct cls;

  cls.mvt = mvt;
  cls.arena = PoolArena(MVTPool(mvt));
  cls.min = min;
  cls.steps = 0;
  cls.hardSteps = 0;

  if (LandIterate(MVTFreeLand(mvt), MVTContingencyVisitor, &cls))
    return FALSE;

  AVER(RangeSize(&cls.range) >= min);
  METER_ACC(mvt->contingencySearches, cls.steps);
  if (cls.hardSteps) {
    METER_ACC(mvt->contingencyHardSearches, cls.hardSteps);
  }
  *baseReturn = RangeBase(&cls.range);
  *limitReturn = RangeLimit(&cls.range);
  return TRUE;
}


/* MVTCheckFit -- verify that segment-aligned block of size min can
 * fit in a candidate address range.
 */

static Bool MVTCheckFit(Addr base, Addr limit, Size min, Arena arena)
{
  Seg seg = NULL;           /* suppress "may be used uninitialized" */
  Addr segLimit;

  SURELY(SegOfAddr(&seg, arena, base));
  segLimit = SegLimit(seg);

  if (limit <= segLimit) {
    if (AddrOffset(base, limit) >= min)
      return TRUE;
  }

  if (AddrOffset(base, segLimit) >= min)
    return TRUE;

  base = segLimit;
  SURELY(SegOfAddr(&seg, arena, base));
  segLimit = SegLimit(seg);

  if (AddrOffset(base, limit < segLimit ? limit : segLimit) >= min)
    return TRUE;

  return FALSE;
}


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
