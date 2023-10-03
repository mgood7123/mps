/* scan.c: SCANNING FUNCTIONS
 *
 * $Id$
 * Copyright (c) 2001-2020 Ravenbrook Limited.
 * See end of file for license.
 *
 * .outside: The code in this file is written as if *outside* the MPS,
 * and so is restricted to facilities in the MPS interface.  MPS users
 * are invited to read this code and use it as a basis for their own
 * scanners.  See topic "Area Scanners" in the MPS manual.
 *
 * TODO: Design document.
 */

#include "mps.h"
#include "mpstd.h" /* for MPS_BUILD_MV */


#ifdef MPS_BUILD_MV
/* MSVC warning 4127 = conditional expression is constant */
/* Objects to: MPS_SCAN_AREA(1). */
#pragma warning( disable : 4127 )
#endif


#define MPS_SCAN_AREA(test) \
  MPS_SCAN_BEGIN(ss) {                                  \
    mps_word_t *p = base;                               \
    while (p < (mps_word_t *)limit) {                   \
      mps_word_t word = *p;                             \
      mps_word_t tag_bits = word & mask;                \
      if (test) {                                       \
        mps_addr_t ref = (mps_addr_t)(word ^ tag_bits); \
        if (MPS_FIX1(ss, ref)) {                        \
          mps_res_t res = MPS_FIX2(ss, &ref);           \
          if (res != MPS_RES_OK)                        \
            return res;                                 \
          *p = (mps_word_t)ref | tag_bits;              \
        }                                               \
      }                                                 \
      ++p;                                              \
    }                                                   \
  } MPS_SCAN_END(ss);

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

/* Convenient internal macro to test version of Clang.  */
#if defined(__clang__) && defined(__clang_major__)
# define MPS_GC_CLANG_PREREQ(major, minor) \
    ((__clang_major__ << 8) + __clang_minor__ >= ((major) << 8) + (minor))
# define MPS_GC_CLANG_PREREQ_FULL(major, minor, patchlevel) \
            (MPS_GC_CLANG_PREREQ(major, (minor) + 1) \
                || (__clang_major__ == (major) && __clang_minor__ == (minor) \
                    && __clang_patchlevel__ >= (patchlevel)))
#else
# define MPS_GC_CLANG_PREREQ(major, minor) 0 /* FALSE */
# define MPS_GC_CLANG_PREREQ_FULL(major, minor, patchlevel) 0
#endif

/* Convenient internal macro to test version of gcc.    */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
# define MPS_GC_GNUC_PREREQ(major, minor) \
            ((__GNUC__ << 8) + __GNUC_MINOR__ >= ((major) << 8) + (minor))
#else
# define MPS_GC_GNUC_PREREQ(major, minor) 0 /* FALSE */
#endif

#ifndef MPS_GC_ATTR_NO_SANITIZE_ADDR
# ifndef MPS_ADDRESS_SANITIZER
#   define MPS_GC_ATTR_NO_SANITIZE_ADDR /* empty */
# elif MPS_GC_CLANG_PREREQ(3, 8)
#   define MPS_GC_ATTR_NO_SANITIZE_ADDR __attribute__((no_sanitize("address")))
# else
#   define MPS_GC_ATTR_NO_SANITIZE_ADDR __attribute__((no_sanitize_address))
# endif
#endif /* !MPS_GC_ATTR_NO_SANITIZE_ADDR */

#ifndef MPS_GC_ATTR_NO_SANITIZE_MEMORY
# ifndef MPS_MEMORY_SANITIZER
#   define MPS_GC_ATTR_NO_SANITIZE_MEMORY /* empty */
# elif MPS_GC_CLANG_PREREQ(3, 8)
#   define MPS_GC_ATTR_NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
# else
#   define MPS_GC_ATTR_NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
# endif
#endif /* !MPS_GC_ATTR_NO_SANITIZE_MEMORY */

#ifndef MPS_GC_ATTR_NO_SANITIZE_THREAD
# ifndef MPS_THREAD_SANITIZER
#   define MPS_GC_ATTR_NO_SANITIZE_THREAD /* empty */
# elif MPS_GC_CLANG_PREREQ(3, 8)
#   define MPS_GC_ATTR_NO_SANITIZE_THREAD __attribute__((no_sanitize("thread")))
# else
    /* It seems that no_sanitize_thread attribute has no effect if the  */
    /* function is inlined (as of gcc 11.1.0, at least).                */
#   ifndef MPS_GC_ATTR_NOINLINE
#    if MPS_GC_GNUC_PREREQ(4, 0)
#      define MPS_GC_ATTR_NOINLINE __attribute__((__noinline__))
#    elif _MSC_VER >= 1400
#      define MPS_GC_ATTR_NOINLINE __declspec(noinline)
#    else
#      define MPS_GC_ATTR_NOINLINE /* empty */
#    endif
#   endif
#   define MPS_GC_ATTR_NO_SANITIZE_THREAD \
                MPS_GC_ATTR_NOINLINE __attribute__((no_sanitize_thread))
# endif
#endif /* !MPS_GC_ATTR_NO_SANITIZE_THREAD */

/* mps_scan_area -- scan contiguous area of references
 *
 * This is a convenience function for scanning the contiguous area
 * [base, limit).  I.e., it calls Fix on all words from base up to
 * limit, inclusive of base and exclusive of limit.
 *
 * This scanner is appropriate for use when all words in the area are
 * simple untagged references.
 */

MPS_GC_ATTR_NO_SANITIZE_ADDR
MPS_GC_ATTR_NO_SANITIZE_MEMORY
MPS_GC_ATTR_NO_SANITIZE_THREAD
mps_res_t mps_scan_area(mps_ss_t ss,
                        void *base, void *limit,
                        void *closure)
{
  mps_word_t mask = 0;

  (void)closure; /* unused */

  MPS_SCAN_AREA(1);

  return MPS_RES_OK;
}


/* mps_scan_area_masked -- scan area masking off tag bits
 *
 * Like mps_scan_area, but removes tag bits before fixing references,
 * and restores them afterwards.
 *
 * For example, if mask is 7, then this scanner will clear the bottom
 * three bits of each word before fixing.
 *
 * This scanner is useful when all words in the area must be treated
 * as references no matter what tag they have.
 */

MPS_GC_ATTR_NO_SANITIZE_ADDR
MPS_GC_ATTR_NO_SANITIZE_MEMORY
MPS_GC_ATTR_NO_SANITIZE_THREAD
mps_res_t mps_scan_area_masked(mps_ss_t ss,
                               void *base, void *limit,
                               void *closure)
{
  mps_scan_tag_t tag = closure;
  mps_word_t mask = tag->mask;

  MPS_SCAN_AREA(1);

  return MPS_RES_OK;
}


/* mps_scan_area_tagged -- scan area selecting by tag
 *
 * Like mps_scan_area_masked, except only references whose masked bits
 * match a particular tag pattern are fixed.
 *
 * For example, if mask is 7 and pattern is 5, then this scanner will
 * only fix words whose low order bits are 0b101.
 */

MPS_GC_ATTR_NO_SANITIZE_ADDR
MPS_GC_ATTR_NO_SANITIZE_MEMORY
MPS_GC_ATTR_NO_SANITIZE_THREAD
mps_res_t mps_scan_area_tagged(mps_ss_t ss,
                               void *base, void *limit,
                               void *closure)
{
  mps_scan_tag_t tag = closure;
  mps_word_t mask = tag->mask;
  mps_word_t pattern = tag->pattern;

  MPS_SCAN_AREA(tag_bits == pattern);

  return MPS_RES_OK;
}


/* mps_scan_area_tagged_or_zero -- scan area selecting by tag or zero
 *
 * Like mps_scan_area_tagged, except references whose masked bits are
 * zero are fixed in addition to those that match the pattern.
 *
 * For example, if mask is 7 and pattern is 3, then this scanner will
 * fix words whose low order bits are 0b011 and words whose low order
 * bits are 0b000, but not any others.
 *
 * This scanner is most useful for ambiguously scanning the stack and
 * registers when using an optimising C compiler and non-zero tags on
 * references, since the compiler is likely to leave untagged
 * addresses of objects around which must not be ignored.
 */

MPS_GC_ATTR_NO_SANITIZE_ADDR
MPS_GC_ATTR_NO_SANITIZE_MEMORY
MPS_GC_ATTR_NO_SANITIZE_THREAD
mps_res_t mps_scan_area_tagged_or_zero(mps_ss_t ss,
                                       void *base, void *limit,
                                       void *closure)
{
  mps_scan_tag_t tag = closure;
  mps_word_t mask = tag->mask;
  mps_word_t pattern = tag->pattern;

  MPS_SCAN_AREA(tag_bits == 0 || tag_bits == pattern);

  return MPS_RES_OK;
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
