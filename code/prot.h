/* prot.h: MEMORY PROTECTION INTERFACE
 *
 * $Id$
 * Copyright (c) 2014-2020 Ravenbrook Limited.  See end of file for license.
 *
 * See <design/prot> for the design of the generic interface including
 * the contracts for these functions.
 *
 * This interface has several different implementations, typically one
 * per platform, see <code/prot*.c> for the various implementations,
 * and <design/prot*> for the corresponding designs.
 */

#ifndef prot_h
#define prot_h

#include "mpmtypes.h"


/* Protection Interface */

extern void ProtSetup(void);
extern Size ProtGranularity(void);
extern void ProtSet(Addr base, Addr limit, AccessSet mode);
extern void ProtSync(Arena arena);


#endif /* prot_h */


/* C. COPYRIGHT AND LICENSE
 *
 * Copyright (C) 2014-2020 Ravenbrook Limited <https://www.ravenbrook.com/>.
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