/* segsmss.c: Segment splitting and merging stress test
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 * Portions copyright (c) 2002 Global Graphics Software.
 *
 * .design: Adapted from amsss.c (because AMS already supports
 * a protocol for subclassing AMS segments). Defines a new pool
 * class, AMST. Segments are split and merged during BufferFill
 * operations. Buffered segments are also split and merged between
 * allocation requests.
 */

#include "mpm.h"
#include "poolams.h"
#include "fmtdy.h"
#include "fmtdytst.h"
#include "testlib.h"
#include "mpslib.h"
#include "locus.h"
#include "mpscams.h"
#include "mpsavm.h"
#include "mpstd.h"
#include "mps.h"

#include <stdio.h> /* fflush, printf, puts, stdout */


/* Start by defining the AMST pool (AMS Test pool) */

#define AMSTSig         ((Sig)0x519A3529) /* SIGnature AMST */

/* AMSTStruct -- AMST pool instance structure */

typedef struct AMSTStruct {
  AMSStruct amsStruct;      /* generic AMS structure */
  Bool failSegs;            /* fail seg splits & merges when true */
  Count splits;             /* count of successful segment splits */
  Count merges;             /* count of successful segment merges */
  Count badSplits;          /* count of unsuccessful segment splits */
  Count badMerges;          /* count of unsuccessful segment merges */
  Count bsplits;            /* count of buffered segment splits */
  Count bmerges;            /* count of buffered segment merges */
  Sig sig;                  /* design.mps.sig.field.end.outer */
} AMSTStruct;

typedef struct AMSTStruct *AMST;

#define PoolAMST(pool) PARENT(AMSTStruct, amsStruct, PARENT(AMSStruct, poolStruct, (pool)))
#define AMST2AMS(amst)  (&(amst)->amsStruct)


typedef AMST AMSTPool;
#define AMSTPoolCheck AMSTCheck
DECLARE_CLASS(Pool, AMSTPool, AMSPool);
DECLARE_CLASS(Seg, AMSTSeg, AMSSeg);


/* AMSTCheck -- the check method for an AMST */

ATTRIBUTE_UNUSED
static Bool AMSTCheck(AMST amst)
{
  CHECKS(AMST, amst);
  CHECKD_NOSIG(AMS, AMST2AMS(amst)); /* <design/check#.hidden-type> */
  return TRUE;
}

/* AMSTFailOperation -- should a split/merge operation fail?
 *
 * returns TRUE if so.
 */
static Bool AMSTFailOperation(AMST amst)
{
  if (amst->failSegs) {
    return rnd() % 2;
  } else {
    return FALSE;
  }
}

/* AMSTSegStruct: AMST segment instances */

#define AMSTSegSig     ((Sig)0x519A3525) /* SIGnature AMST Seg */

typedef struct AMSTSegStruct *AMSTSeg;

typedef struct AMSTSegStruct {
  AMSSegStruct amsSegStruct; /* superclass fields must come first */
  AMSTSeg next;          /* mergeable next segment, or NULL */
  AMSTSeg prev;          /* mergeable prev segment, or NULL */
  Sig sig;               /* design.mps.sig.field.end.outer */
} AMSTSegStruct;



/* AMSTSegCheck -- check the AMST segment */

ATTRIBUTE_UNUSED
static Bool AMSTSegCheck(AMSTSeg amstseg)
{
  CHECKS(AMSTSeg, amstseg);
  CHECKD_NOSIG(AMSSeg, &amstseg->amsSegStruct); /* <design/check#.hidden-type> */
  /* don't bother to do other checks - this is a stress test */
  return TRUE;
}

#define Seg2AMSTSeg(seg)             ((AMSTSeg)(seg))
#define AMSTSeg2Seg(amstseg)         ((Seg)(amstseg))


/* amstSegInit -- initialise an amst segment */

static Res amstSegInit(Seg seg, Pool pool, Addr base, Size size, ArgList args)
{
  AMSTSeg amstseg;
  AMST amst;
  Res res;

  /* Initialize the superclass fields first via next-method call */
  res = NextMethod(Seg, AMSTSeg, init)(seg, pool, base, size, args);
  if (res != ResOK)
    return res;
  amstseg = CouldBeA(AMSTSeg, seg);

  AVERT(Pool, pool);
  amst = PoolAMST(pool);
  AVERT(AMST, amst);
  /* no useful checks for base and size */

  amstseg->next = NULL;
  amstseg->prev = NULL;

  SetClassOfPoly(seg, CLASS(AMSTSeg));
  amstseg->sig = AMSTSegSig;
  AVERC(AMSTSeg, amstseg);

  return ResOK;
}


/* amstSegFinish -- Finish method for AMST segments */

static void amstSegFinish(Inst inst)
{
  Seg seg = MustBeA(Seg, inst);
  AMSTSeg amstseg = MustBeA(AMSTSeg, seg);

  AVERT(AMSTSeg, amstseg);

  if (amstseg->next != NULL)
    amstseg->next->prev = NULL;
  if (amstseg->prev != NULL)
    amstseg->prev->next = NULL;

  amstseg->sig = SigInvalid;
  /* finish the superclass fields last */
  NextMethod(Inst, AMSTSeg, finish)(inst);
}



/* amstSegMerge -- AMSTSeg merge method
 *
 * .fail: Test proper handling of the most complex failure cases
 * by deliberately detecting failure sometimes after calling the
 * next method. We handle the error by calling the anti-method.
 * This isn't strictly safe <design/poolams#.split-merge.fail>.
 * But we assume here that we won't run out of memory when calling the
 * anti-method.
 */
static Res amstSegMerge(Seg seg, Seg segHi,
                        Addr base, Addr mid, Addr limit)
{
  AMST amst;
  AMSTSeg amstseg, amstsegHi;
  Res res;

  AVERT(Seg, seg);
  AVERT(Seg, segHi);
  amstseg = Seg2AMSTSeg(seg);
  amstsegHi = Seg2AMSTSeg(segHi);
  AVERT(AMSTSeg, amstseg);
  AVERT(AMSTSeg, amstsegHi);
  amst = PoolAMST(SegPool(seg));

  /* Merge the superclass fields via direct next-method call */
  res = NextMethod(Seg, AMSTSeg, merge)(seg, segHi, base, mid, limit);
  if (res != ResOK)
    goto failSuper;

  if (AMSTFailOperation(amst)) {
    amst->badMerges++;
    printf("D");
    goto failDeliberate;
  }

  amstseg->next = amstsegHi->next;
  amstsegHi->sig = SigInvalid;
  AVERT(AMSTSeg, amstseg);
  amst->merges++;
  printf("M");
  return ResOK;

failDeliberate:
  /* Call the anti-method (see .fail) */
  res = NextMethod(Seg, AMSTSeg, split)(seg, segHi, base, mid, limit);
  AVER(res == ResOK);
  res = ResFAIL;
failSuper:
  AVERT(AMSTSeg, amstseg);
  AVERT(AMSTSeg, amstsegHi);
  return res;
}


/* amstSegSplit -- AMSTSeg split method */

static Res amstSegSplit(Seg seg, Seg segHi,
                        Addr base, Addr mid, Addr limit)
{
  AMST amst;
  AMSTSeg amstseg, amstsegHi;
  Res res;

  AVERT(Seg, seg);
  AVER(segHi != NULL);  /* can't check fully, it's not initialized */
  amstseg = Seg2AMSTSeg(seg);
  amstsegHi = Seg2AMSTSeg(segHi);
  AVERT(AMSTSeg, amstseg);
  amst = PoolAMST(SegPool(seg));

  /* Split the superclass fields via direct next-method call */
  res = NextMethod(Seg, AMSTSeg, split)(seg, segHi, base, mid, limit);
  if (res != ResOK)
    goto failSuper;

  if (AMSTFailOperation(amst)) {
    amst->badSplits++;
    printf("B");
    goto failDeliberate;
  }

  /* Full initialization for segHi. */
  amstsegHi->next = amstseg->next;
  amstsegHi->prev = amstseg;
  amstsegHi->sig = AMSTSegSig;
  amstseg->next = amstsegHi;
  AVERT(AMSTSeg, amstseg);
  AVERT(AMSTSeg, amstsegHi);
  amst->splits++;
  printf("S");
  return ResOK;

failDeliberate:
  /* Call the anti-method. (see .fail) */
  res = NextMethod(Seg, AMSTSeg, merge)(seg, segHi, base, mid, limit);
  AVER(res == ResOK);
  res = ResFAIL;
failSuper:
  AVERT(AMSTSeg, amstseg);
  return res;
}


/* AMSTSegClass -- Class definition for AMST segments */

DEFINE_CLASS(Seg, AMSTSeg, klass)
{
  INHERIT_CLASS(klass, AMSTSeg, AMSSeg);
  klass->instClassStruct.finish = amstSegFinish;
  klass->size = sizeof(AMSTSegStruct);
  klass->init = amstSegInit;
  klass->split = amstSegSplit;
  klass->merge = amstSegMerge;
  AVERT(SegClass, klass);
}


/* AMSTSegSizePolicy
 *
 * Picks double the default segment size.
 */
static Res AMSTSegSizePolicy(Size *sizeReturn,
                             Pool pool, Size size, RankSet rankSet)
{
  Arena arena;
  Size basic, want;

  AVER(sizeReturn != NULL);
  AVERT(Pool, pool);
  AVER(size > 0);
  AVERT(RankSet, rankSet);

  arena = PoolArena(pool);

  basic = SizeArenaGrains(size, arena);
  if (basic == 0) {
    /* overflow */
    return ResMEMORY;
  }
  want = basic + basic;
  if (want <= basic) {
    /* overflow */
    return ResMEMORY;
  }
  *sizeReturn = want;
  return ResOK;
}


/* AMSTInit -- the pool class initialization method */

static Res AMSTInit(Pool pool, Arena arena, PoolClass klass, ArgList args)
{
  AMST amst;
  AMS ams;
  Res res;

  res = NextMethod(Pool, AMSTPool, init)(pool, arena, klass, args);
  if (res != ResOK)
    return res;

  amst = CouldBeA(AMSTPool, pool);
  ams = MustBeA(AMSPool, pool);

  ams->segSize = AMSTSegSizePolicy;
  ams->segClass = AMSTSegClassGet;
  amst->failSegs = TRUE;
  amst->splits = 0;
  amst->merges = 0;
  amst->badSplits = 0;
  amst->badMerges = 0;
  amst->bsplits = 0;
  amst->bmerges = 0;

  SetClassOfPoly(pool, CLASS(AMSTPool));
  amst->sig = AMSTSig;
  AVERC(AMSTPool, amst);

  return ResOK;
}


/* AMSTFinish -- the pool class finish method */

static void AMSTFinish(Inst inst)
{
  Pool pool = MustBeA(AbstractPool, inst);
  AMST amst = MustBeA(AMSTPool, pool);

  AVERT(AMST, amst);

  amst->sig = SigInvalid;

  printf("\nDestroying pool, having performed:\n");
  printf("    %"PRIuLONGEST" splits          (S)\n", (ulongest_t)amst->splits);
  printf("    %"PRIuLONGEST" merges          (M)\n", (ulongest_t)amst->merges);
  printf("    %"PRIuLONGEST" aborted splits  (B)\n", (ulongest_t)amst->badSplits);
  printf("    %"PRIuLONGEST" aborted merges  (D)\n", (ulongest_t)amst->badMerges);
  printf("  which included:\n");
  printf("    %"PRIuLONGEST" buffered splits (C)\n", (ulongest_t)amst->bsplits);
  printf("    %"PRIuLONGEST" buffered merges (J)\n", (ulongest_t)amst->bmerges);

  NextMethod(Inst, AMSTPool, finish)(inst);
}


/* AMSSegIsFree -- return TRUE if a seg is all unallocated */

static Bool AMSSegIsFree(Seg seg)
{
  AMSSeg amsseg;
  AVERT(Seg, seg);
  amsseg = Seg2AMSSeg(seg);
  return amsseg->freeGrains == amsseg->grains;
}


/* AMSSegRegionIsFree -- return TRUE if a region is all unallocated */

static Bool AMSSegRegionIsFree(Seg seg, Addr base, Addr limit)
{
  AMSSeg amsseg = MustBeA(AMSSeg, seg);
  Index baseIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), base);

  if (amsseg->allocTableInUse) {
    Index limitIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), limit);
    return BTIsResRange(amsseg->allocTable, baseIndex, limitIndex);
  } else {
    return amsseg->firstFree <= baseIndex;
  }
}


/* AMSUnallocateRange -- set a range to be unallocated
 *
 * Used as a means of overriding the behaviour of AMSBufferFill.
 * The code is similar to amsSegBufferEmpty.
 */
static void AMSUnallocateRange(AMS ams, Seg seg, Addr base, Addr limit)
{
  AMSSeg amsseg;
  Index baseIndex, limitIndex;
  Count unallocatedGrains;
  /* parameters checked by caller */

  amsseg = Seg2AMSSeg(seg);

  baseIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), base);
  limitIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), limit);

  if (amsseg->allocTableInUse) {
    /* check that it's allocated */
    AVER(BTIsSetRange(amsseg->allocTable, baseIndex, limitIndex));
    BTResRange(amsseg->allocTable, baseIndex, limitIndex);
  } else {
    /* check that it's allocated */
    AVER(limitIndex <= amsseg->firstFree);
    if (limitIndex == amsseg->firstFree) /* is it at the end? */ {
      amsseg->firstFree = baseIndex;
    } else { /* start using allocTable */
      amsseg->allocTableInUse = TRUE;
      BTSetRange(amsseg->allocTable, 0, amsseg->firstFree);
      if (amsseg->firstFree < amsseg->grains)
        BTResRange(amsseg->allocTable, amsseg->firstFree, amsseg->grains);
      BTResRange(amsseg->allocTable, baseIndex, limitIndex);
    }
  }

  unallocatedGrains = limitIndex - baseIndex;
  AVER(amsseg->bufferedGrains >= unallocatedGrains);
  amsseg->freeGrains += unallocatedGrains;
  amsseg->bufferedGrains -= unallocatedGrains;
  PoolGenAccountForEmpty(ams->pgen, 0,
                         PoolGrainsSize(AMSPool(ams), unallocatedGrains),
                         FALSE);
}


/* AMSAllocateRange -- set a range to be allocated
 *
 * Used as a means of overriding the behaviour of AMSBufferFill.
 * The code is similar to AMSUnallocateRange.
 */
static void AMSAllocateRange(AMS ams, Seg seg, Addr base, Addr limit)
{
  AMSSeg amsseg;
  Index baseIndex, limitIndex;
  Count allocatedGrains;
  /* parameters checked by caller */

  amsseg = Seg2AMSSeg(seg);

  baseIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), base);
  limitIndex = PoolIndexOfAddr(SegBase(seg), SegPool(seg), limit);

  if (amsseg->allocTableInUse) {
    /* check that it's not allocated */
    AVER(BTIsResRange(amsseg->allocTable, baseIndex, limitIndex));
    BTSetRange(amsseg->allocTable, baseIndex, limitIndex);
  } else {
    /* check that it's not allocated */
    AVER(baseIndex >= amsseg->firstFree);
    if (baseIndex == amsseg->firstFree) /* is it at the end? */ {
      amsseg->firstFree = limitIndex;
    } else { /* start using allocTable */
      amsseg->allocTableInUse = TRUE;
      BTSetRange(amsseg->allocTable, 0, amsseg->firstFree);
      if (amsseg->firstFree < amsseg->grains)
        BTResRange(amsseg->allocTable, amsseg->firstFree, amsseg->grains);
      BTSetRange(amsseg->allocTable, baseIndex, limitIndex);
    }
  }

  allocatedGrains = limitIndex - baseIndex;
  AVER(amsseg->freeGrains >= allocatedGrains);
  amsseg->freeGrains -= allocatedGrains;
  amsseg->bufferedGrains += allocatedGrains;
  PoolGenAccountForFill(ams->pgen, AddrOffset(base, limit));
}


/* AMSTBufferFill -- the pool class buffer fill method
 *
 * Calls next method - but possibly splits or merges the chosen
 * segment.
 *
 * .merge: A merge is performed when the next method returns the
 * entire segment, this segment had previously been split from the
 * segment below, and the segment below is appropriately similar
 * (i.e. not already attached to a buffer and similarly coloured)
 *
 * .split: If we're not merging, a split is performed if the next method
 * returns the entire segment, and yet lower half of the segment would
 * meet the request.
 */
static Res AMSTBufferFill(Addr *baseReturn, Addr *limitReturn,
                          Pool pool, Buffer buffer, Size size)
{
  Addr base, limit;
  Arena arena;
  AMS ams;
  AMST amst;
  Bool b;
  Seg seg;
  AMSTSeg amstseg;
  Res res;

  AVERT(Pool, pool);
  AVER(baseReturn != NULL);
  AVER(limitReturn != NULL);
  /* other parameters are checked by next method */
  arena = PoolArena(pool);
  ams = PoolAMS(pool);
  amst = PoolAMST(pool);

  /* call next method */
  res = NextMethod(Pool, AMSTPool, bufferFill)(&base, &limit, pool, buffer, size);
  if (res != ResOK)
    return res;

  b = SegOfAddr(&seg, arena, base);
  AVER(b);
  amstseg = Seg2AMSTSeg(seg);

  if (SegLimit(seg) == limit && SegBase(seg) == base) {
    if (amstseg->prev != NULL) {
      Seg segLo = AMSTSeg2Seg(amstseg->prev);
      if (!SegHasBuffer(segLo) &&
          SegGrey(segLo) == SegGrey(seg) &&
          SegWhite(segLo) == SegWhite(seg)) {
        /* .merge */
        Seg mergedSeg;
        Res mres;

        AMSUnallocateRange(ams, seg, base, limit);
        mres = SegMerge(&mergedSeg, segLo, seg);
        if (ResOK == mres) { /* successful merge */
          AMSAllocateRange(ams, mergedSeg, base, limit);
          /* leave range as-is */
        } else {            /* failed to merge */
          AVER(amst->failSegs); /* deliberate fails only */
          AMSAllocateRange(ams, seg, base, limit);
        }
      }

    } else {
      Size half = SegSize(seg) / 2;
      if (half >= size && SizeIsArenaGrains(half, arena)) {
        /* .split */
        Addr mid = AddrAdd(base, half);
        Seg segLo, segHi;
        Res sres;
        AMSUnallocateRange(ams, seg, mid, limit);
        sres = SegSplit(&segLo, &segHi, seg, mid);
        if (ResOK == sres) { /* successful split */
          limit = mid;  /* range is lower segment */
        } else {            /* failed to split */
          AVER(amst->failSegs); /* deliberate fails only */
          AMSAllocateRange(ams, seg, mid, limit);
        }

      }
    }
  }

  *baseReturn = base;
  *limitReturn = limit;
  return ResOK;
}


/* AMSTStressBufferedSeg -- Stress test for a buffered seg
 *
 * Test splitting or merging a buffered seg.
 *
 * .bmerge: A merge is performed when the segment had previously
 * been split and the segment above meets the constraints (i.e. empty,
 * not already attached to a buffer and similar colour)
 *
 * .bsplit: Whether or not a merge happened, a split is performed if
 * the limit of the buffered region is also the limit of an arena
 * grain, and yet does not correspond to the segment limit, provided
 * that the part of the segment above the buffer is all free.
 */
static void AMSTStressBufferedSeg(Seg seg, Buffer buffer)
{
  AMSTSeg amstseg;
  AMST amst;
  Arena arena;
  Addr limit;
  Buffer segBuf;

  AVERT(Seg, seg);
  AVERT(Buffer, buffer);
  AVER(SegBuffer(&segBuf, seg) && segBuf == buffer);
  amstseg = Seg2AMSTSeg(seg);
  AVERT(AMSTSeg, amstseg);
  limit = BufferLimit(buffer);
  arena = PoolArena(SegPool(seg));
  amst = PoolAMST(SegPool(seg));
  AVERT(AMST, amst);

  if (amstseg->next != NULL) {
    Seg segHi = AMSTSeg2Seg(amstseg->next);
    if (AMSSegIsFree(segHi) && SegGrey(segHi) == SegGrey(seg)) {
      /* .bmerge */
      Seg mergedSeg;
      Res res;
      res = SegMerge(&mergedSeg, seg, segHi);
      if (ResOK == res) {
        amst->bmerges++;
        printf("J");
      } else {
        /* deliberate fails only */
        AVER(amst->failSegs);
      }
    }
  }

  if (SegLimit(seg) != limit &&
      AddrIsArenaGrain(limit, arena) &&
      AMSSegRegionIsFree(seg, limit, SegLimit(seg))) {
    /* .bsplit */
    Seg segLo, segHi;
    Res res;
    res = SegSplit(&segLo, &segHi, seg, limit);
    if (ResOK == res) {
      amst->bsplits++;
      printf("C");
    } else {
      /* deliberate fails only */
      AVER(amst->failSegs);
    }
  }
}



/* AMSTPoolClass -- the pool class definition */

DEFINE_CLASS(Pool, AMSTPool, klass)
{
  INHERIT_CLASS(klass, AMSTPool, AMSPool);
  klass->instClassStruct.finish = AMSTFinish;
  klass->size = sizeof(AMSTStruct);
  klass->init = AMSTInit;
  klass->bufferFill = AMSTBufferFill;
  AVERT(PoolClass, klass);
}


/* mps_amst_ap_stress -- stress an active buffer
 *
 * Attempt to either split or merge a segment attached to an AP
 */
static void mps_amst_ap_stress(mps_ap_t ap)
{
  Buffer buffer;
  Seg seg;

  buffer = BufferOfAP(ap);
  AVERT(Buffer, buffer);
  seg = BufferSeg(buffer);
  AMSTStressBufferedSeg(seg, buffer);
}


/* mps_class_amst -- return the pool class descriptor to the client */

static mps_pool_class_t mps_class_amst(void)
{
  return (mps_pool_class_t)CLASS(AMSTPool);
}


/* AMS collection parameters */

#define exactRootsCOUNT 50
#define ambigRootsCOUNT 100
#define sizeScale       4
/* This is enough for five GCs. */
#define totalSizeMAX    sizeScale * 800 * (size_t)1024
#define totalSizeSTEP   200 * (size_t)1024
/* objNULL needs to be odd so that it's ignored in exactRoots. */
#define objNULL         ((mps_addr_t)MPS_WORD_CONST(0xDECEA5ED))
#define testArenaSIZE   ((size_t)16<<20)
#define initTestFREQ    6000
#define stressTestFREQ  40


/* static variables for the test */

static mps_pool_t pool;
static mps_ap_t ap;
static mps_addr_t exactRoots[exactRootsCOUNT];
static mps_addr_t ambigRoots[ambigRootsCOUNT];
static size_t totalSize = 0;


/* make -- object allocation and init */

static mps_addr_t make(void)
{
  size_t length = rnd() % 20, size = (length+2) * sizeof(mps_word_t);
  mps_addr_t p;
  mps_res_t res;

  do {
    MPS_RESERVE_BLOCK(res, p, ap, size);
    if (res)
      die(res, "MPS_RESERVE_BLOCK");
    res = dylan_init(p, size, exactRoots, exactRootsCOUNT);
    if (res)
      die(res, "dylan_init");
  } while(!mps_commit(ap, p, size));

  totalSize += size;
  return p;
}


/* test -- the actual stress test */

static void test(mps_arena_t arena)
{
  mps_fmt_t format;
  mps_root_t exactRoot, ambigRoot;
  size_t lastStep = 0, i, r;
  unsigned long objs;
  mps_ap_t busy_ap;
  mps_addr_t busy_init;
  const char *indent = "    ";
  mps_chain_t chain;
  static mps_gen_param_s genParam = {1024, 0.2};

  die(mps_fmt_create_A(&format, arena, dylan_fmt_A()), "fmt_create");
  die(mps_chain_create(&chain, arena, 1, &genParam), "chain_create");

  MPS_ARGS_BEGIN(args) {
    MPS_ARGS_ADD(args, MPS_KEY_FORMAT, format);
    MPS_ARGS_ADD(args, MPS_KEY_CHAIN, chain);
    MPS_ARGS_ADD(args, MPS_KEY_GEN, 0);
    die(mps_pool_create_k(&pool, arena, mps_class_amst(), args),
        "pool_create(amst)");
  } MPS_ARGS_END(args);

  die(mps_ap_create(&ap, pool, mps_rank_exact()), "BufferCreate");
  die(mps_ap_create(&busy_ap, pool, mps_rank_exact()), "BufferCreate 2");

  for(i = 0; i < exactRootsCOUNT; ++i)
    exactRoots[i] = objNULL;
  for(i = 0; i < ambigRootsCOUNT; ++i)
    ambigRoots[i] = rnd_addr();

  die(mps_root_create_table_masked(&exactRoot, arena,
                                   mps_rank_exact(), (mps_rm_t)0,
                                   &exactRoots[0], exactRootsCOUNT,
                                   (mps_word_t)1),
      "root_create_table(exact)");
  die(mps_root_create_table(&ambigRoot, arena,
                            mps_rank_ambig(), (mps_rm_t)0,
                            &ambigRoots[0], ambigRootsCOUNT),
      "root_create_table(ambig)");

  puts(indent);

  /* create an ap, and leave it busy */
  die(mps_reserve(&busy_init, busy_ap, 64), "mps_reserve busy");

  objs = 0;
  while(totalSize < totalSizeMAX) {
    if (totalSize > lastStep + totalSizeSTEP) {
      lastStep = totalSize;
      printf("\nSize %"PRIuLONGEST" bytes, %"PRIuLONGEST" objects.\n",
             (ulongest_t)totalSize, (ulongest_t)objs);
      printf("%s", indent);
      (void)fflush(stdout);
      for(i = 0; i < exactRootsCOUNT; ++i)
        cdie(exactRoots[i] == objNULL || dylan_check(exactRoots[i]),
             "all roots check");
    }

    r = (size_t)rnd();
    if (r & 1) {
      i = (r >> 1) % exactRootsCOUNT;
      if (exactRoots[i] != objNULL)
        cdie(dylan_check(exactRoots[i]), "dying root check");
      exactRoots[i] = make();
      if (exactRoots[(exactRootsCOUNT-1) - i] != objNULL)
        dylan_write(exactRoots[(exactRootsCOUNT-1) - i],
                    exactRoots, exactRootsCOUNT);
    } else {
      i = (r >> 1) % ambigRootsCOUNT;
      ambigRoots[(ambigRootsCOUNT-1) - i] = make();
      /* Create random interior pointers */
      ambigRoots[i] = (mps_addr_t)((char *)(ambigRoots[i/2]) + 1);
    }

    if (rnd() % stressTestFREQ == 0)
      mps_amst_ap_stress(ap); /* stress active buffer */

    if (rnd() % initTestFREQ == 0)
      *(int*)busy_init = -1; /* check that the buffer is still there */

    ++objs;
    if (objs % 256 == 0) {
      printf(".");
      (void)fflush(stdout);
    }
  }

  (void)mps_commit(busy_ap, busy_init, 64);

  mps_arena_park(arena);
  mps_ap_destroy(busy_ap);
  mps_ap_destroy(ap);
  mps_root_destroy(exactRoot);
  mps_root_destroy(ambigRoot);
  mps_pool_destroy(pool);
  mps_chain_destroy(chain);
  mps_fmt_destroy(format);
}


int main(int argc, char *argv[])
{
  mps_arena_t arena;
  mps_thr_t thread;

  testlib_init(argc, argv);

  die(mps_arena_create(&arena, mps_arena_class_vm(), testArenaSIZE),
      "arena_create");
  die(mps_thread_reg(&thread, arena), "thread_reg");
  test(arena);
  mps_thread_dereg(thread);
  mps_arena_destroy(arena);

  printf("%s: Conclusion: Failed to find any defects.\n", argv[0]);
  return 0;
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
