/* arenacl.c: ARENA CLASS USING CLIENT MEMORY
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * .design: <design/arena#.client>.
 *
 * .improve.remember: One possible performance improvement is to
 * remember (a conservative approximation to) the indices of the first
 * and last free pages in each chunk, and start searching from these
 * in ChunkAlloc.  See request.epcore.170534_.
 *
 * .. _request.epcore.170534: https://info.ravenbrook.com/project/mps/import/2001-11-05/mmprevol/request/epcore/170534
 */

#include "boot.h"
#include "tract.h"
#include "bt.h"
#include "mpm.h"
#include "mpsacl.h"

SRCID(arenacl, "$Id$");

DECLARE_CLASS(Arena, ClientArena, AbstractArena);


/* ClientArenaStruct -- Client Arena Structure */

#define ClientArenaSig ((Sig)0x519A6EC7) /* SIGnature AREna CLient */

typedef struct ClientArenaStruct {
  ArenaStruct arenaStruct; /* generic arena structure */
  Sig sig;                 /* design.mps.sig.field.end.outer */
} ClientArenaStruct;
typedef struct ClientArenaStruct *ClientArena;


/* CLChunk -- chunk structure */

typedef struct ClientChunkStruct *ClientChunk;

#define ClientChunkSig ((Sig)0x519A6C2C) /* SIGnature ARena CLient Chunk */

typedef struct ClientChunkStruct {
  ChunkStruct chunkStruct;     /* generic chunk */
  Size freePages;              /* number of free pages in chunk */
  Addr pageBase;               /* base of first managed page in chunk */
  Sig sig;                     /* design.mps.sig.field.end.outer */
} ClientChunkStruct;

#define ClientChunk2Chunk(clchunk) (&(clchunk)->chunkStruct)
#define Chunk2ClientChunk(chunk) PARENT(ClientChunkStruct, chunkStruct, chunk)


/* ClientChunkClientArena -- get the client arena from a client chunk */

#define ClientChunkClientArena(clchunk) \
  Arena2ClientArena(ChunkArena(ClientChunk2Chunk(clchunk)))


/* ClientChunkCheck -- check the consistency of a client chunk */

ATTRIBUTE_UNUSED
static Bool ClientChunkCheck(ClientChunk clChunk)
{
  Chunk chunk;

  CHECKS(ClientChunk, clChunk);
  chunk = ClientChunk2Chunk(clChunk);
  CHECKD(Chunk, chunk);
  CHECKL(clChunk->freePages <= chunk->pages);
  /* check they don't overlap (knowing the order) */
  CHECKL((Addr)(chunk + 1) < (Addr)chunk->allocTable);
  return TRUE;
}


/* ClientArenaCheck -- check the consistency of a client arena */

ATTRIBUTE_UNUSED
static Bool ClientArenaCheck(ClientArena clientArena)
{
  Arena arena = MustBeA(AbstractArena, clientArena);

  /* See <code/arena.c#.reserved.check> */
  CHECKL(arena->committed <= arena->reserved);
  CHECKL(arena->spareCommitted == 0);

  return TRUE;
}


/* clientChunkCreate -- create a ClientChunk */

static Res clientChunkCreate(Chunk *chunkReturn, ClientArena clientArena,
                             Addr base, Addr limit)
{
  Arena arena = MustBeA(AbstractArena, clientArena);
  ClientChunk clChunk;
  Chunk chunk;
  Addr alignedBase;
  BootBlockStruct bootStruct;
  BootBlock boot = &bootStruct;
  Res res;
  void *p;

  AVER(chunkReturn != NULL);
  AVER(base != (Addr)0);
  AVER(limit != (Addr)0);
  AVER(limit > base);

  /* Initialize boot block. */
  /* Chunk has to be page-aligned, and the boot allocs must be within it. */
  alignedBase = AddrAlignUp(base, ArenaGrainSize(arena));
  AVER(alignedBase < limit);
  res = BootBlockInit(boot, (void *)alignedBase, (void *)limit);
  if (res != ResOK)
    goto failBootInit;

  /* Allocate the chunk. */
  /* TODO: Add reference to design. */
  res = BootAlloc(&p, boot, sizeof(ClientChunkStruct), MPS_PF_ALIGN);
  if (res != ResOK)
    goto failChunkAlloc;
  clChunk = p;
  chunk = ClientChunk2Chunk(clChunk);

  res = ChunkInit(chunk, arena, alignedBase,
                  AddrAlignDown(limit, ArenaGrainSize(arena)),
                  AddrOffset(base, limit), boot);
  if (res != ResOK)
    goto failChunkInit;

  arena->committed += ChunkPagesToSize(chunk, chunk->allocBase);

  BootBlockFinish(boot);

  clChunk->sig = ClientChunkSig;
  AVERT(ClientChunk, clChunk);
  *chunkReturn = chunk;
  return ResOK;

failChunkInit:
failChunkAlloc:
failBootInit:
  return res;
}


/* ClientChunkInit -- initialize a ClientChunk */

static Res ClientChunkInit(Chunk chunk, BootBlock boot)
{
  Res res;
  ClientChunk clChunk;
  void *p;

  /* chunk is supposed to be uninitialized, so don't check it. */
  clChunk = Chunk2ClientChunk(chunk);
  AVERT(BootBlock, boot);

  /* TODO: An old comment claimed this is too large.
     Does it fail to exclude the page table or something? */
  clChunk->freePages = chunk->pages;

  /* Put the page table as late as possible, as in VM systems we don't want */
  /* to map it. */
  res = BootAlloc(&p, boot, chunk->pageTablePages << chunk->pageShift, chunk->pageSize);
  if (res != ResOK)
    return res;
  chunk->pageTable = p;

  return ResOK;
}


/* clientChunkDestroy -- destroy a ClientChunk */

static Bool clientChunkDestroy(Tree tree, void *closure)
{
  Arena arena;
  Chunk chunk;
  ClientChunk clChunk;
  Size size;

  AVERT(Tree, tree);
  AVER(closure == UNUSED_POINTER);
  UNUSED(closure);

  chunk = ChunkOfTree(tree);
  AVERT(Chunk, chunk);
  arena = ChunkArena(chunk);
  AVERT(Arena, arena);
  clChunk = Chunk2ClientChunk(chunk);
  AVERT(ClientChunk, clChunk);
  AVER(chunk->pages == clChunk->freePages);

  size = ChunkPagesToSize(chunk, chunk->allocBase);
  AVER(arena->committed >= size);
  arena->committed -= size;

  clChunk->sig = SigInvalid;
  ChunkFinish(chunk);

  return TRUE;
}


/* ClientChunkFinish -- finish a ClientChunk */

static void ClientChunkFinish(Chunk chunk)
{
  /* Can't check chunk as it's not valid anymore. */
  UNUSED(chunk);
}


/* ClientArenaVarargs -- parse obsolete varargs */

static void ClientArenaVarargs(ArgStruct args[MPS_ARGS_MAX], va_list varargs)
{
  args[0].key = MPS_KEY_ARENA_SIZE;
  args[0].val.size = va_arg(varargs, Size);
  args[1].key = MPS_KEY_ARENA_CL_BASE;
  args[1].val.addr = va_arg(varargs, Addr);
  args[2].key = MPS_KEY_ARGS_END;
  AVERT(ArgList, args);
}


/* ClientArenaInit -- create and initialize the client arena
 *
 * .init.memory: Creates the arena structure in the chuck given, and
 * makes the first chunk from the memory left over.
 * .arena.init: Once the arena has been allocated, we call ArenaInit
 * to do the generic part of init.
 */

ARG_DEFINE_KEY(ARENA_CL_BASE, Addr);

static Res ClientArenaCreate(Arena *arenaReturn, ArgList args)
{
  Arena arena;
  ClientArena clientArena;
  Size size;
  Size clArenaSize;   /* aligned size of ClientArenaStruct */
  Addr base, limit, chunkBase;
  Align grainSize = 1;
  Res res;
  Chunk chunk;
  mps_arg_s arg;

  AVER(arenaReturn != NULL);
  AVERT(ArgList, args);

  ArgRequire(&arg, args, MPS_KEY_ARENA_SIZE);
  size = arg.val.size;
  ArgRequire(&arg, args, MPS_KEY_ARENA_CL_BASE);
  base = arg.val.addr;
  if (ArgPick(&arg, args, MPS_KEY_ARENA_GRAIN_SIZE))
    grainSize = arg.val.size;
  grainSize = SizeAlignUp(grainSize, ARENA_CLIENT_GRAIN_SIZE);
  grainSize = SizeAlignUp(grainSize, ProtGranularity());

  AVER(base != (Addr)0);
  AVERT(ArenaGrainSize, grainSize);

  if (size < grainSize * MPS_WORD_WIDTH)
    /* Not enough room for a full complement of zones. */
    return ResMEMORY;

  clArenaSize = SizeAlignUp(sizeof(ClientArenaStruct), MPS_PF_ALIGN);
  if (size < clArenaSize)
    return ResMEMORY;

  limit = AddrAdd(base, size);

  /* allocate the arena */
  base = AddrAlignUp(base, MPS_PF_ALIGN);
  clientArena = (ClientArena)base;
  chunkBase = AddrAlignUp(AddrAdd(base, clArenaSize), MPS_PF_ALIGN);
  if (chunkBase > limit)
    return ResMEMORY;

  arena = CouldBeA(AbstractArena, clientArena);

  res = NextMethod(Arena, ClientArena, init)(arena, grainSize, args);
  if (res != ResOK)
    goto failSuperInit;
  SetClassOfPoly(arena, CLASS(ClientArena));
  AVER(clientArena == MustBeA(ClientArena, arena));

  /* have to have a valid arena before calling ChunkCreate */
  clientArena->sig = ClientArenaSig;

  res = clientChunkCreate(&chunk, clientArena, chunkBase, limit);
  if (res != ResOK)
    goto failChunkCreate;
  arena->primary = chunk;

  /* Set the zone shift to divide the initial chunk into the same */
  /* number of zones as will fit into a reference set (the number of */
  /* bits in a word). Note that some zones are discontiguous in the */
  /* arena if the size is not a power of 2. */
  arena->zoneShift = SizeFloorLog2(size >> MPS_WORD_SHIFT);
  AVER(ArenaGrainSize(arena) == ChunkPageSize(arena->primary));

  EVENT7(ArenaCreateCL, arena, size, base, grainSize,
         ClassOfPoly(Arena, arena), ArenaGlobals(arena)->systemPools,
         arena->serial);
  AVERT(ClientArena, clientArena);
  *arenaReturn = arena;
  return ResOK;

failChunkCreate:
  NextMethod(Inst, ClientArena, finish)(MustBeA(Inst, arena));
failSuperInit:
  AVER(res != ResOK);
  return res;
}


/* ClientArenaDestroy -- destroy the arena */

static void ClientArenaDestroy(Arena arena)
{
  ClientArena clientArena = MustBeA(ClientArena, arena);

  /* Destroy all chunks, including the primary. See
   * <design/arena#.chunk.delete> */
  arena->primary = NULL;
  TreeTraverseAndDelete(&arena->chunkTree, clientChunkDestroy,
                        UNUSED_POINTER);

  clientArena->sig = SigInvalid;

  /* Destroying the chunks should leave nothing behind. */
  AVER(arena->reserved == 0);
  AVER(arena->committed == 0);

  NextMethod(Inst, ClientArena, finish)(MustBeA(Inst, arena));
}


/* ClientArenaExtend -- extend the arena */

static Res ClientArenaExtend(Arena arena, Addr base, Size size)
{
  ClientArena clientArena = MustBeA(ClientArena, arena);
  Chunk chunk;

  AVER(base != (Addr)0);
  AVER(size > 0);

  return clientChunkCreate(&chunk, clientArena, base, AddrAdd(base, size));
}


/* ClientArenaPagesMarkAllocated -- Mark the pages allocated */

static Res ClientArenaPagesMarkAllocated(Arena arena, Chunk chunk,
                                         Index baseIndex, Count pages,
                                         Pool pool)
{
  Index i;
  ClientChunk clChunk;

  AVERT(Arena, arena);
  AVERT(Chunk, chunk);
  clChunk = Chunk2ClientChunk(chunk);
  AVERT(ClientChunk, clChunk);
  AVER(chunk->allocBase <= baseIndex);
  AVER(pages > 0);
  AVER(baseIndex + pages <= chunk->pages);
  AVERT(Pool, pool);

  for (i = 0; i < pages; ++i)
    PageAlloc(chunk, baseIndex + i, pool);

  arena->committed += ChunkPagesToSize(chunk, pages);
  AVER(clChunk->freePages >= pages);
  clChunk->freePages -= pages;

  return ResOK;
}


/* ClientChunkPageMapped -- determine if a page is mapped */

static Bool ClientChunkPageMapped(Chunk chunk, Index index)
{
  UNUSED(chunk);
  UNUSED(index);

  AVERT(Chunk, chunk);
  AVER(index < chunk->pages);

  return TRUE;
}


/* ClientArenaFree - free a region in the arena */

static void ClientArenaFree(Addr base, Size size, Pool pool)
{
  Arena arena;
  Chunk chunk = NULL;           /* suppress "may be used uninitialized" */
  Size pages;
  Index pi, baseIndex, limitIndex;
  Bool foundChunk;
  ClientChunk clChunk;

  AVER(base != NULL);
  AVER(size > (Size)0);
  AVERT(Pool, pool);
  arena = PoolArena(pool);
  AVERC(ClientArena, arena);
  AVER(SizeIsAligned(size, ChunkPageSize(arena->primary)));
  AVER(AddrIsAligned(base, ChunkPageSize(arena->primary)));

  foundChunk = ChunkOfAddr(&chunk, arena, base);
  AVER(foundChunk);
  clChunk = Chunk2ClientChunk(chunk);
  AVERT(ClientChunk, clChunk);

  pages = ChunkSizeToPages(chunk, size);
  baseIndex = INDEX_OF_ADDR(chunk, base);
  limitIndex = baseIndex + pages;
  AVER(baseIndex < limitIndex);
  AVER(limitIndex <= chunk->pages);

  for(pi = baseIndex; pi < limitIndex; pi++) {
    Tract tract = PageTract(ChunkPage(chunk, pi));

    AVER(TractPool(tract) == pool);
    TractFinish(tract);
  }

  AVER(BTIsSetRange(chunk->allocTable, baseIndex, limitIndex));
  BTResRange(chunk->allocTable, baseIndex, limitIndex);

  AVER(arena->committed >= size);
  arena->committed -= size;
  clChunk->freePages += pages;
}


/* ClientArenaClass  -- The Client arena class definition */

DEFINE_CLASS(Arena, ClientArena, klass)
{
  INHERIT_CLASS(klass, ClientArena, AbstractArena);
  klass->size = sizeof(ClientArenaStruct);
  klass->varargs = ClientArenaVarargs;
  klass->create = ClientArenaCreate;
  klass->destroy = ClientArenaDestroy;
  klass->extend = ClientArenaExtend;
  klass->pagesMarkAllocated = ClientArenaPagesMarkAllocated;
  klass->free = ClientArenaFree;
  klass->chunkInit = ClientChunkInit;
  klass->chunkFinish = ClientChunkFinish;
  klass->chunkPageMapped = ClientChunkPageMapped;
  AVERT(ArenaClass, klass);
}


/* mps_arena_class_cl -- return the arena class CL */

mps_arena_class_t mps_arena_class_cl(void)
{
  return (mps_arena_class_t)CLASS(ClientArena);
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
