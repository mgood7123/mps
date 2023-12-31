/* root.c: ROOT IMPLEMENTATION
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * .purpose: This is the implementation of the root datatype.
 *
 * .design: For design, see <design/root> and
 * <design/root-interface>. */

#include "mpm.h"

SRCID(root, "$Id$");


/* RootStruct -- tracing root structure */

#define RootSig         ((Sig)0x51960029) /* SIGnature ROOT */

typedef union AreaScanUnion {
  void *closure;
  mps_scan_tag_s tag;       /* tag for scanning */
} AreaScanUnion;

typedef struct RootStruct {
  Sig sig;                      /* design.mps.sig.field */
  Serial serial;                /* from arena->rootSerial */
  Arena arena;                  /* owning arena */
  RingStruct arenaRing;         /* attachment to arena */
  Rank rank;                    /* rank of references in this root */
  TraceSet grey;                /* traces for which root is grey */
  RefSet summary;               /* summary of references in root */
  RootMode mode;                /* mode */
  Bool protectable;             /* Can protect root? */
  Addr protBase;                /* base of protectable area */
  Addr protLimit;               /* limit of protectable area */
  AccessSet pm;                 /* Protection Mode */
  RootVar var;                  /* union discriminator */
  union RootUnion {
    struct {
      mps_root_scan_t scan;     /* the function which does the scanning */
      void *p;                  /* closure for scan function */
      size_t s;                 /* closure for scan function */
    } fun;
    struct {
      Word *base;               /* base of area to be scanned */
      Word *limit;              /* limit of area to be scanned */
      mps_area_scan_t scan_area;/* area scanning function */
      AreaScanUnion the;
    } area;
    struct {
      Thread thread;            /* passed to scan */
      mps_area_scan_t scan_area;/* area scanner for stack and registers */
      AreaScanUnion the;
      void *stackCold;          /* cold end of stack */
    } thread;
    struct {
      mps_fmt_scan_t scan;      /* format-like scanner */
      Addr base, limit;         /* passed to scan */
    } fmt;
  } the;
} RootStruct;


/* RootVarCheck -- check a Root union discriminator
 *
 * .rootvarcheck: Synchronize with <code/mpmtypes.h#rootvar> */

Bool RootVarCheck(RootVar rootVar)
{
  CHECKL(rootVar == RootAREA || rootVar == RootAREA_TAGGED
         || rootVar == RootFUN || rootVar == RootFMT
         || rootVar == RootTHREAD
         || rootVar == RootTHREAD_TAGGED);
  UNUSED(rootVar);
  return TRUE;
}


/* RootModeCheck */

Bool RootModeCheck(RootMode mode)
{
  CHECKL((mode & (RootModeCONSTANT | RootModePROTECTABLE
                  | RootModePROTECTABLE_INNER))
         == mode);
  /* RootModePROTECTABLE_INNER implies RootModePROTECTABLE */
  CHECKL((mode & RootModePROTECTABLE_INNER) == 0
         || (mode & RootModePROTECTABLE));
  UNUSED(mode);

  return TRUE;
}


/* RootCheck -- check the consistency of a root structure
 *
 * .rootcheck: Keep synchronized with <code/mpmst.h#root>. */

Bool RootCheck(Root root)
{
  CHECKS(Root, root);
  CHECKU(Arena, root->arena);
  CHECKL(root->serial < ArenaGlobals(root->arena)->rootSerial);
  CHECKD_NOSIG(Ring, &root->arenaRing);
  CHECKL(RankCheck(root->rank));
  CHECKL(TraceSetCheck(root->grey));
  /* Don't need to check var here, because of the switch below */
  switch(root->var)
  {
  case RootAREA:
    CHECKL(root->the.area.base != 0);
    CHECKL(root->the.area.base < root->the.area.limit);
    CHECKL(FUNCHECK(root->the.area.scan_area));
    /* Can't check anything about closure */
    break;

  case RootAREA_TAGGED:
    CHECKL(root->the.area.base != 0);
    CHECKL(root->the.area.base < root->the.area.limit);
    CHECKL(FUNCHECK(root->the.area.scan_area));
    /* Can't check anything about tag as it could mean anything to
       scan_area. */
    break;

  case RootFUN:
    CHECKL(root->the.fun.scan != NULL);
    /* Can't check anything about closure as it could mean anything to
       scan. */
    break;

  case RootTHREAD:
    CHECKD_NOSIG(Thread, root->the.thread.thread); /* <design/check#.hidden-type> */
    CHECKL(FUNCHECK(root->the.thread.scan_area));
    /* Can't check anything about closure as it could mean anything to
       scan_area. */
    /* Can't check anything about stackCold. */
    break;

  case RootTHREAD_TAGGED:
    CHECKD_NOSIG(Thread, root->the.thread.thread); /* <design/check#.hidden-type> */
    CHECKL(FUNCHECK(root->the.thread.scan_area));
    /* Can't check anything about tag as it could mean anything to
       scan_area. */
    /* Can't check anything about stackCold. */
    break;

  case RootFMT:
    CHECKL(root->the.fmt.scan != NULL);
    CHECKL(root->the.fmt.base != 0);
    CHECKL(root->the.fmt.base < root->the.fmt.limit);
    break;

  default:
    NOTREACHED;
  }
  CHECKL(RootModeCheck(root->mode));
  CHECKL(BoolCheck(root->protectable));
  if (root->protectable) {
    CHECKL(root->protBase != (Addr)0);
    CHECKL(root->protLimit != (Addr)0);
    CHECKL(root->protBase < root->protLimit);
    CHECKL(AccessSetCheck(root->pm));
  } else {
    CHECKL(root->protBase == (Addr)0);
    CHECKL(root->protLimit == (Addr)0);
    CHECKL(root->pm == (AccessSet)0);
  }
  return TRUE;
}


/* rootCreate, RootCreateArea, RootCreateThread, RootCreateFmt, RootCreateFun
 *
 * RootCreate* set up the appropriate union member, and call the generic
 * create function to do the actual creation
 *
 * See <design/root#.init> for initial value. */

static Res rootCreate(Root *rootReturn, Arena arena,
                      Rank rank, RootMode mode, RootVar type,
                      union RootUnion *theUnionP)
{
  Root root;
  Res res;
  void *p;
  Globals globals;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(RootMode, mode);
  AVERT(RootVar, type);
  globals = ArenaGlobals(arena);

  res = ControlAlloc(&p, arena, sizeof(RootStruct));
  if (res != ResOK)
    return res;
  root = (Root)p; /* Avoid pun */

  root->arena = arena;
  root->rank = rank;
  root->var = type;
  root->the  = *theUnionP;
  root->grey = TraceSetEMPTY;
  root->summary = RefSetUNIV;
  root->mode = mode;
  root->pm = AccessSetEMPTY;
  root->protectable = FALSE;
  root->protBase = (Addr)0;
  root->protLimit = (Addr)0;

  /* <design/arena#.root-ring> */
  RingInit(&root->arenaRing);

  root->serial = globals->rootSerial;
  ++globals->rootSerial;
  root->sig = RootSig;

  AVERT(Root, root);

  RingAppend(&globals->rootRing, &root->arenaRing);

  *rootReturn = root;
  return ResOK;
}

static Res rootCreateProtectable(Root *rootReturn, Arena arena,
                                 Rank rank, RootMode mode, RootVar var,
                                 Addr base, Addr limit,
                                 union RootUnion *theUnion)
{
  Res res;
  Root root;
  Ring node, next;

  res = rootCreate(&root, arena, rank, mode, var, theUnion);
  if (res != ResOK)
    return res;
  if (mode & RootModePROTECTABLE) {
    root->protectable = TRUE;
    if (mode & RootModePROTECTABLE_INNER) {
      root->protBase = AddrArenaGrainUp(base, arena);
      root->protLimit = AddrArenaGrainDown(limit, arena);
      if (!(root->protBase < root->protLimit)) {
        /* root had no inner pages */
        root->protectable = FALSE;
        root->mode &=~ (RootModePROTECTABLE|RootModePROTECTABLE_INNER);
      }
    } else {
      root->protBase = AddrArenaGrainDown(base, arena);
      root->protLimit = AddrArenaGrainUp(limit, arena);
    }
  }

  /* Check that this root doesn't intersect with any other root */
  RING_FOR(node, &ArenaGlobals(arena)->rootRing, next) {
    Root trial = RING_ELT(Root, arenaRing, node);
    if (trial != root) {
      /* (trial->protLimit <= root->protBase */
      /*  || root->protLimit <= trial->protBase) */
      /* is the "okay" state.  The negation of this is: */
      if (root->protBase < trial->protLimit
          && trial->protBase < root->protLimit) {
        NOTREACHED;
        RootDestroy(root);
        return ResFAIL;
      }
    }
  }

  AVERT(Root, root);

  *rootReturn = root;
  return ResOK;
}

Res RootCreateArea(Root *rootReturn, Arena arena,
                   Rank rank, RootMode mode,
                   Word *base, Word *limit,
                   mps_area_scan_t scan_area,
                   void *closure)
{
  Res res;
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(RootMode, mode);
  AVER(base != 0);
  AVER(AddrIsAligned(base, sizeof(Word)));
  AVER(base < limit);
  AVER(AddrIsAligned(limit, sizeof(Word)));
  AVER(FUNCHECK(scan_area));
  /* Can't check anything about closure */

  theUnion.area.base = base;
  theUnion.area.limit = limit;
  theUnion.area.scan_area = scan_area;
  theUnion.area.the.closure = closure;

  res = rootCreateProtectable(rootReturn, arena, rank, mode,
                              RootAREA, (Addr)base, (Addr)limit, &theUnion);
  return res;
}

Res RootCreateAreaTagged(Root *rootReturn, Arena arena,
                         Rank rank, RootMode mode, Word *base, Word *limit,
                         mps_area_scan_t scan_area, Word mask, Word pattern)
{
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(RootMode, mode);
  AVER(base != 0);
  AVER(base < limit);
  /* Can't check anything about mask or pattern, as they could mean
     anything to scan_area. */

  theUnion.area.base = base;
  theUnion.area.limit = limit;
  theUnion.area.scan_area = scan_area;
  theUnion.area.the.tag.mask = mask;
  theUnion.area.the.tag.pattern = pattern;

  return rootCreateProtectable(rootReturn, arena, rank, mode, RootAREA_TAGGED,
                               (Addr)base, (Addr)limit, &theUnion);
}

Res RootCreateThread(Root *rootReturn, Arena arena,
                     Rank rank, Thread thread,
                     mps_area_scan_t scan_area,
                     void *closure,
                     Word *stackCold)
{
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(Thread, thread);
  AVER(ThreadArena(thread) == arena);
  AVER(FUNCHECK(scan_area));
  /* Can't check anything about closure. */

  theUnion.thread.thread = thread;
  theUnion.thread.scan_area = scan_area;
  theUnion.thread.the.closure = closure;
  theUnion.thread.stackCold = stackCold;

  return rootCreate(rootReturn, arena, rank, (RootMode)0, RootTHREAD,
                    &theUnion);
}

Res RootCreateThreadTagged(Root *rootReturn, Arena arena,
                           Rank rank, Thread thread,
                           mps_area_scan_t scan_area,
                           Word mask, Word pattern,
                           Word *stackCold)
{
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(Thread, thread);
  AVER(ThreadArena(thread) == arena);
  AVER(FUNCHECK(scan_area));
  /* Can't check anything about mask or pattern, as they could mean
     anything to scan_area. */

  theUnion.thread.thread = thread;
  theUnion.thread.scan_area = scan_area;
  theUnion.thread.the.tag.mask = mask;
  theUnion.thread.the.tag.pattern = pattern;
  theUnion.thread.stackCold = stackCold;

  return rootCreate(rootReturn, arena, rank, (RootMode)0, RootTHREAD_TAGGED,
                    &theUnion);
}

/* RootCreateFmt -- create root from block of formatted objects
 *
 * .fmt.no-align-check: Note that we don't check the alignment of base
 * and limit. That's because we're only given the scan function, so we
 * don't know the format's alignment requirements.
 */

Res RootCreateFmt(Root *rootReturn, Arena arena,
                  Rank rank, RootMode mode, mps_fmt_scan_t scan,
                  Addr base, Addr limit)
{
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVERT(RootMode, mode);
  AVER(FUNCHECK(scan));
  AVER(base != 0);
  AVER(base < limit);

  theUnion.fmt.scan = scan;
  theUnion.fmt.base = base;
  theUnion.fmt.limit = limit;

  return rootCreateProtectable(rootReturn, arena, rank, mode,
                               RootFMT, base, limit, &theUnion);
}

Res RootCreateFun(Root *rootReturn, Arena arena, Rank rank,
                  mps_root_scan_t scan, void *p, size_t s)
{
  union RootUnion theUnion;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  AVERT(Rank, rank);
  AVER(FUNCHECK(scan));

  theUnion.fun.scan = scan;
  theUnion.fun.p = p;
  theUnion.fun.s = s;

  return rootCreate(rootReturn, arena, rank, (RootMode)0, RootFUN, &theUnion);
}


/* RootDestroy -- destroy a root */

void RootDestroy(Root root)
{
  Arena arena;

  AVERT(Root, root);

  arena = RootArena(root);

  AVERT(Arena, arena);

  RingRemove(&root->arenaRing);
  RingFinish(&root->arenaRing);

  root->sig = SigInvalid;

  ControlFree(arena, root, sizeof(RootStruct));
}


/* RootArena -- return the arena of a root
 *
 * Must be thread-safe. <design/interface-c#.check.testt> */

Arena RootArena(Root root)
{
  AVER(TESTT(Root, root));
  return root->arena;
}


/* RootRank -- return the rank of a root */

Rank RootRank(Root root)
{
  AVERT(Root, root);
  return root->rank;
}


/* RootPM -- return the protection mode of a root */

AccessSet RootPM(Root root)
{
  AVERT(Root, root);
  return root->pm;
}


/* RootSummary -- return the summary of a root */

RefSet RootSummary(Root root)
{
  AVERT(Root, root);
  return root->summary;
}


/* RootGrey -- mark root grey */

void RootGrey(Root root, Trace trace)
{
  AVERT(Root, root);
  AVERT(Trace, trace);

  root->grey = TraceSetAdd(root->grey, trace);
}


static void rootSetSummary(Root root, RefSet summary)
{
  AVERT(Root, root);
  /* Can't check summary */
  if (root->protectable) {
    if (summary == RefSetUNIV) {
      root->summary = summary;
      root->pm &= ~AccessWRITE;
    } else {
      root->pm |= AccessWRITE;
      root->summary = summary;
    }
  } else
    AVER(root->summary == RefSetUNIV);
}


/* RootScan -- scan root */

Res RootScan(ScanState ss, Root root)
{
  Res res;

  AVERT(Root, root);
  AVERT(ScanState, ss);
  AVER(root->rank == ss->rank);

  if (TraceSetInter(root->grey, ss->traces) == TraceSetEMPTY)
    return ResOK;

  AVER(ScanStateSummary(ss) == RefSetEMPTY);

  if (root->pm != AccessSetEMPTY) {
    ProtSet(root->protBase, root->protLimit, AccessSetEMPTY);
  }

  switch(root->var) {
  case RootAREA:
    res = TraceScanArea(ss,
                        root->the.area.base,
                        root->the.area.limit,
                        root->the.area.scan_area,
                        root->the.area.the.closure);
    if (res != ResOK)
      goto failScan;
    break;

  case RootAREA_TAGGED:
    res = TraceScanArea(ss,
                        root->the.area.base,
                        root->the.area.limit,
                        root->the.area.scan_area,
                        &root->the.area.the.tag);
    if (res != ResOK)
      goto failScan;
    break;

  case RootFUN:
    res = root->the.fun.scan(&ss->ss_s,
                             root->the.fun.p,
                             root->the.fun.s);
    if (res != ResOK)
      goto failScan;
    break;

  case RootTHREAD:
    res = ThreadScan(ss, root->the.thread.thread,
                     root->the.thread.stackCold,
                     root->the.thread.scan_area,
                     root->the.thread.the.closure);
    if (res != ResOK)
      goto failScan;
    break;

  case RootTHREAD_TAGGED:
    res = ThreadScan(ss, root->the.thread.thread,
                     root->the.thread.stackCold,
                     root->the.thread.scan_area,
                     &root->the.thread.the.tag);
    if (res != ResOK)
      goto failScan;
    break;

  case RootFMT:
    res = (*root->the.fmt.scan)(&ss->ss_s, root->the.fmt.base, root->the.fmt.limit);
    ss->scannedSize += AddrOffset(root->the.fmt.base, root->the.fmt.limit);
    if (res != ResOK)
      goto failScan;
    break;

  default:
    NOTREACHED;
    res = ResUNIMPL;
    goto failScan;
  }

  AVER(res == ResOK);
  root->grey = TraceSetDiff(root->grey, ss->traces);
  rootSetSummary(root, ScanStateSummary(ss));
  EVENT3(RootScan, root, ss->traces, ScanStateSummary(ss));

failScan:
  if (root->pm != AccessSetEMPTY) {
    ProtSet(root->protBase, root->protLimit, root->pm);
  }

  return res;
}


/* RootOfAddr -- return the root at addr
 *
 * Returns TRUE if the addr is in a root (and returns the root in
 * *rootReturn) otherwise returns FALSE.  Cf. SegOfAddr.  */

Bool RootOfAddr(Root *rootReturn, Arena arena, Addr addr)
{
  Ring node, next;

  AVER(rootReturn != NULL);
  AVERT(Arena, arena);
  /* addr is arbitrary and can't be checked */

  RING_FOR(node, &ArenaGlobals(arena)->rootRing, next) {
    Root root = RING_ELT(Root, arenaRing, node);

    if (root->protectable && root->protBase <= addr && addr < root->protLimit) {
      *rootReturn = root;
      return TRUE;
    }
  }

  return FALSE;
}


/* RootAccess -- handle barrier hit on root */

void RootAccess(Root root, AccessSet mode)
{
  AVERT(Root, root);
  AVERT(AccessSet, mode);
  AVER((root->pm & mode) != AccessSetEMPTY);
  AVER(mode == AccessWRITE); /* only write protection supported */

  rootSetSummary(root, RefSetUNIV);

  /* Access must now be allowed. */
  AVER((root->pm & mode) == AccessSetEMPTY);
  ProtSet(root->protBase, root->protLimit, root->pm);
}


/* RootsIterate -- iterate over all the roots in the arena */

Res RootsIterate(Globals arena, RootIterateFn f, void *p)
{
  Res res = ResOK;
  Ring node, next;

  RING_FOR(node, &arena->rootRing, next) {
    Root root = RING_ELT(Root, arenaRing, node);

    res = (*f)(root, p);
    if (res != ResOK)
      return res;
  }
  return res;
}


/* RootDescribe -- describe a root */

Res RootDescribe(Root root, mps_lib_FILE *stream, Count depth)
{
  Res res;

  if (!TESTT(Root, root))
    return ResFAIL;
  if (stream == NULL)
    return ResFAIL;

  res = WriteF(stream, depth,
               "Root $P ($U) {\n", (WriteFP)root, (WriteFU)root->serial,
               "  arena $P ($U)\n", (WriteFP)root->arena,
               (WriteFU)root->arena->serial,
               "  rank $U\n", (WriteFU)root->rank,
               "  grey $B\n", (WriteFB)root->grey,
               "  summary $B\n", (WriteFB)root->summary,
               "  mode",
               root->mode == 0 ? " NONE" : "",
               root->mode & RootModeCONSTANT ? " CONSTANT" : "",
               root->mode & RootModePROTECTABLE ? " PROTECTABLE" : "",
               root->mode & RootModePROTECTABLE_INNER ? " INNER" : "",
               "\n",
               "  protectable $S", WriteFYesNo(root->protectable),
               "  protBase $A", (WriteFA)root->protBase,
               "  protLimit $A", (WriteFA)root->protLimit,
               "  pm",
               root->pm == AccessSetEMPTY ? " EMPTY" : "",
               root->pm & AccessREAD ? " READ" : "",
               root->pm & AccessWRITE ? " WRITE" : "",
               NULL);
  if (res != ResOK)
    return res;

  switch(root->var) {
  case RootAREA:
    res = WriteF(stream, depth + 2,
                 "area base $A limit $A scan_area closure $P\n",
                 (WriteFA)root->the.area.base,
                 (WriteFA)root->the.area.limit,
                 (WriteFP)root->the.area.the.closure,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  case RootAREA_TAGGED:
    res = WriteF(stream, depth + 2,
                 "area base $A limit $A scan_area mask $B pattern $B\n",
                 (WriteFA)root->the.area.base,
                 (WriteFA)root->the.area.limit,
                 (WriteFB)root->the.area.the.tag.mask,
                 (WriteFB)root->the.area.the.tag.pattern,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  case RootFUN:
    res = WriteF(stream, depth + 2,
                 "scan function $F\n", (WriteFF)root->the.fun.scan,
                 "environment p $P s $W\n",
                 (WriteFP)root->the.fun.p,
                 (WriteFW)root->the.fun.s,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  case RootTHREAD:
    res = WriteF(stream, depth + 2,
                 "thread $P\n", (WriteFP)root->the.thread.thread,
                 "closure $P\n",
                 (WriteFP)root->the.thread.the.closure,
                 "stackCold $P\n", (WriteFP)root->the.thread.stackCold,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  case RootTHREAD_TAGGED:
    res = WriteF(stream, depth + 2,
                 "thread $P\n", (WriteFP)root->the.thread.thread,
                 "mask $B\n", (WriteFB)root->the.thread.the.tag.mask,
                 "pattern $B\n", (WriteFB)root->the.thread.the.tag.pattern,
                 "stackCold $P\n", (WriteFP)root->the.thread.stackCold,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  case RootFMT:
    res = WriteF(stream, depth + 2,
                 "scan function $F\n", (WriteFF)root->the.fmt.scan,
                 "format base $A limit $A\n",
                 (WriteFA)root->the.fmt.base, (WriteFA)root->the.fmt.limit,
                 NULL);
    if (res != ResOK)
      return res;
    break;

  default:
    NOTREACHED;
  }

  res = WriteF(stream, depth,
               "} Root $P ($U)\n", (WriteFP)root, (WriteFU)root->serial,
               NULL);
  if (res != ResOK)
    return res;

  return ResOK;
}


/* RootsDescribe -- describe all roots */

Res RootsDescribe(Globals arenaGlobals, mps_lib_FILE *stream, Count depth)
{
  Res res = ResOK;
  Ring node, next;

  RING_FOR(node, &arenaGlobals->rootRing, next) {
    Root root = RING_ELT(Root, arenaRing, node);
    res = RootDescribe(root, stream, depth);
    if (res != ResOK)
      return res;
  }
  return res;
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
