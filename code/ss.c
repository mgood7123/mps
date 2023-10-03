/* ss.c: STACK SCANNING
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.  See end of file for license.
 *
 * This scans the mutator's stack and fixes the registers that may
 * contain roots. <design/stack-scan>.
 *
 * This is a generic implementation, but it makes assumptions that,
 * while true on all the platforms we currently (version 1.115)
 * support, may not be true on all platforms. See
 * <design/stack-scan#.sol.platform>.
 *
 * .assume.desc: The stack is descending (and so stackHot is a lower
 * address than stackCold).
 *
 * .assume.full: The stack convention is "full" (and so we must scan
 * the word pointed to by stackHot but not the word pointed to by
 * stackCold).
 */

#include "mpm.h"

SRCID(ss, "$Id$");


/* StackHot -- capture a hot stack pointer
 *
 * On all supported platforms, the arguments are pushed on to the
 * stack by the caller below its other local data, so as long as
 * it does not use something like alloca, the address of the argument
 * is a hot stack pointer.  <design/ss#.sol.stack.hot>.
 */

ATTRIBUTE_NOINLINE
void StackHot(void **stackOut)
{
// ASAN SUPPORT

#if defined(__has_feature)
  /* __has_feature() is supported.      */
# if __has_feature(address_sanitizer)
#   define MPS_ADDRESS_SANITIZER
# endif
# if __has_feature(memory_sanitizer)
#   define MPS_MEMORY_SANITIZER
# endif
# if __has_feature(thread_sanitizer)
#   define MPS_THREAD_SANITIZER
# endif
#else
# ifdef __SANITIZE_ADDRESS__
    /* GCC v4.8+ */
#   define MPS_ADDRESS_SANITIZER
# endif
# if defined(__SANITIZE_THREAD__)
    /* GCC v7.1+ */
#   define MPS_THREAD_SANITIZER
# endif
#endif /* !__has_feature */

# ifdef MPS_ADDRESS_SANITIZER
    // asan uses a fake stack, obtain the real stack

    /* Define word and signed word to be unsigned and signed types of the   */
    /* size as char* or void*.                                              */
    /* A macro to define integer types of a pointer size.  There seems to   */
    /* be no way to do this even semi-portably.  The following is probably  */
    /* no better/worse than almost anything else.                           */
    /* The ANSI standard suggests that size_t and ptrdiff_t might be        */
    /* better choices.  But those had incorrect definitions on some older   */
    /* systems; notably "typedef int size_t" is wrong.                      */
#    ifdef _WIN64
#     if defined(__int64) && !defined(CPPCHECK)
#       define MPS_GC_SIGNEDWORD __int64
#     else
#       define MPS_GC_SIGNEDWORD long long
#     endif
#    else
#     define MPS_GC_SIGNEDWORD long
#    endif

#    define MPS_GC_UNSIGNEDWORD unsigned MPS_GC_SIGNEDWORD

    typedef MPS_GC_UNSIGNEDWORD MPS_GC_word;

    typedef MPS_GC_word MPS_word;

    volatile MPS_word sp;

#   if defined(__ANDROID__) && !defined(HOST_ANDROID)
     /* __ANDROID__ macro is defined by Android NDK gcc.   */
#    define HOST_ANDROID 1
#   endif

    /* First a unified test for Linux: */
#   if (defined(linux) || defined(__linux__) || defined(HOST_ANDROID)) \
       && !defined(LINUX) && !defined(__native_client__)
#     define LINUX
#   endif

#   if defined(__e2k__) && defined(LINUX)
#      define E2K
#   elif defined(__s390__) && defined(LINUX)
#      define S390
#   endif

#   if ((defined(E2K) && defined(__clang__)) \
        || (defined(S390) && (__clang_major__ < 8))) && !defined(CPPCHECK)
        /* Workaround some bugs in clang:                                   */
        /* "undefined reference to llvm.frameaddress" error (clang-9/e2k);  */
        /* a crash in SystemZTargetLowering of libLLVM-3.8 (S390).          */
        sp = (MPS_word)&sp;
#   elif defined(CPPCHECK) || (__GNUC__ >= 4 /* MANAGED_STACK_ADDRESS_BOEHM_GC_GNUC_PREREQ(4, 0) */ \
                               && !defined(MPS_STACK_NOT_SCANNED))
        /* TODO: Use MANAGED_STACK_ADDRESS_BOEHM_GC_GNUC_PREREQ after fixing a bug in cppcheck. */
        sp = (MPS_word)__builtin_frame_address(0);
#   else
        sp = (MPS_word)&sp;
#   endif
                /* Also force stack to grow if necessary. Otherwise the */
                /* later accesses might cause the kernel to think we're */
                /* doing something wrong.                               */
    *stackOut = (void*)sp;
# else
  *stackOut = &stackOut;
# endif
}


/* StackScan -- scan the mutator's stack and registers */

Res StackScan(ScanState ss, void *stackCold,
              mps_area_scan_t scan_area, void *closure)
{
  StackContextStruct scStruct;
  Arena arena;
  /* Avoid the error "variable might be clobbered by 'longjmp'" from
     GCC by specifying volatile. See job004113. */
  void * volatile warmest;

  AVERT(ScanState, ss);

  arena = ss->arena;

  AVER(arena->stackWarm != NULL);
  warmest = arena->stackWarm;
  if (warmest == NULL) {
    /* Somehow missed saving the context at the entry point
       <design/stack-scan#.sol.entry-points.fragile>: do it now. */
    warmest = &scStruct;
    STACK_CONTEXT_SAVE(&scStruct);
  }

  AVER(warmest < stackCold);                            /* .assume.desc */

  return TraceScanArea(ss, warmest, stackCold, scan_area, closure);
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
