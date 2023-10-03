/* 
TEST_HEADER
 id = $Id$
 summary = null stack pointer for mps_root_create_thread
 language = c
 link = testlib.o
OUTPUT_SPEC
 assert = true
 assertfile P= mpsi.c
 assertcond = cold != NULL
END_HEADER
*/

#include "testlib.h"
#include "arg.h"

static void test(void *stack_pointer)
{
 mps_arena_t arena;
 mps_thr_t thread;
 mps_root_t root;

 cdie(mps_arena_create(&arena, mps_arena_class_vm(), mmqaArenaSIZE), "create arena");

 cdie(mps_thread_reg(&thread, arena), "register thread");

 cdie(mps_root_create_thread(&root, arena, thread, NULL), "thread root");
}

int main(void)
{
 run_test(test);
 return 0;
}
