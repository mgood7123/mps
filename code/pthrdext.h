/* pthreadext.h: POSIX THREAD EXTENSIONS
 *
 *  $Id$
 *  Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * .readership: MM developers.
 *
 *  .purpose: Provides extension to Pthreads.
 */

#ifndef pthreadext_h
#define pthreadext_h

#include <signal.h>

#include "mpm.h"


#define PThreadextSig ((Sig)0x519B286E) /* SIGnature PTHReadExt */


/* PThreadext -- extension datatype  */

typedef struct PThreadextStruct *PThreadext;


/* PThreadextStruct -- structure definition
 *
 * Should be embedded in a client structure
 */

typedef struct PThreadextStruct {
  Sig sig;                         /* design.mps.sig.field */
  pthread_t id;                    /* Thread ID */
  MutatorContext context;          /* context if suspended */
  RingStruct threadRing;           /* ring of suspended threads */
  RingStruct idRing;               /* duplicate suspensions for id */
} PThreadextStruct;



/*  PThreadextCheck -- Check a pthreadext */

extern Bool PThreadextCheck(PThreadext pthreadext);


/*  PThreadextInit -- Initialize a pthreadext */

extern void PThreadextInit(PThreadext pthreadext, pthread_t id);


/*  PThreadextFinish -- Finish a pthreadext */

extern void PThreadextFinish(PThreadext pthreadext);


/*  PThreadextSuspend -- Suspend a pthreadext and return its context. */

extern Res PThreadextSuspend(PThreadext pthreadext,
                             MutatorContext *contextReturn);


/*  PThreadextResume --  Resume a suspended pthreadext */

extern Res PThreadextResume(PThreadext pthreadext);


#endif /* pthreadext_h */


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
