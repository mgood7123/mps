/* splay.h: SPLAY TREE HEADER
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * .source: <design/splay>
 */

#ifndef splay_h
#define splay_h

#include "mpmtypes.h" /* for Res, etc. */
#include "tree.h"


typedef struct SplayTreeStruct *SplayTree;

typedef Bool (*SplayTestNodeFunction)(SplayTree splay, Tree node,
                                      void *closure);
typedef Bool (*SplayTestTreeFunction)(SplayTree splay, Tree node,
                                      void *closure);

typedef void (*SplayUpdateNodeFunction)(SplayTree splay, Tree node);
extern void SplayTrivUpdate(SplayTree splay, Tree node);

#define SplayTreeSig      ((Sig)0x5195B1A1) /* SIGnature SPLAY */

typedef struct SplayTreeStruct {
  Sig sig; /* design.mps.sig.field */
  TreeCompareFunction compare;
  TreeKeyFunction nodeKey;
  SplayUpdateNodeFunction updateNode;
  Tree root;
} SplayTreeStruct;

#define SplayTreeRoot(splay)    RVALUE((splay)->root)
#define SplayTreeIsEmpty(splay) (SplayTreeRoot(splay) == TreeEMPTY)

extern Bool SplayTreeCheck(SplayTree splay);
extern void SplayTreeInit(SplayTree splay,
                          TreeCompareFunction compare,
                          TreeKeyFunction nodeKey,
                          SplayUpdateNodeFunction updateNode);
extern void SplayTreeFinish(SplayTree splay);

extern Bool SplayTreeInsert(SplayTree splay, Tree node);
extern Bool SplayTreeDelete(SplayTree splay, Tree node);

extern Bool SplayTreeFind(Tree *nodeReturn, SplayTree splay, TreeKey key);

extern Bool SplayTreeNeighbours(Tree *leftReturn,
                                Tree *rightReturn,
                                SplayTree splay, TreeKey key);

extern Tree SplayTreeFirst(SplayTree splay);
extern Tree SplayTreeNext(SplayTree splay, TreeKey oldKey);

typedef Bool (*SplayFindFunction)(Tree *nodeReturn, SplayTree splay,
                                  SplayTestNodeFunction testNode,
                                  SplayTestTreeFunction testTree,
                                  void *closure);
extern Bool SplayFindFirst(Tree *nodeReturn, SplayTree splay,
                           SplayTestNodeFunction testNode,
                           SplayTestTreeFunction testTree,
                           void *closure);
extern Bool SplayFindLast(Tree *nodeReturn, SplayTree splay,
                          SplayTestNodeFunction testNode,
                          SplayTestTreeFunction testTree,
                          void *closure);

extern void SplayNodeRefresh(SplayTree splay, Tree node);
extern void SplayNodeInit(SplayTree splay, Tree node);

extern Res SplayTreeDescribe(SplayTree splay, mps_lib_FILE *stream,
                             Count depth, TreeDescribeFunction nodeDescribe);

extern void SplayDebugUpdate(SplayTree splay, Tree tree);
extern Count SplayDebugCount(SplayTree splay);


#endif /* splay_h */


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
