#include <elf.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "crossld.h"

static void print(char *c) {
  printf("Also maybe this will work?\n");
  fprintf(stderr, "From 64bit code: [%s]\n", c);
}

static void print_long_long(long long x) {
  printf("printing: %lld\n", x);
}

long long test_ll(long long p) {
  printf("before ll %lld\n", p);
  return p;
}

unsigned long test_ul(unsigned long p) {
  printf("before lu: %lu\n", p);
  return p;
}

void* test_ptr(void * ptr) {
  printf("before ptr: %p\n", ptr);
  return ptr;
}

void *too_big_ptr() {
  printf("before crash\n");
  return (void*)(1LL << 33);
}

int main(int argc, char *argv[]) {
  if (argc < 2)
    exit(2);


  enum type print_types[] = {TYPE_PTR};
  type pul_t[] = {TYPE_UNSIGNED_LONG};
  type pll_t[] = {TYPE_LONG_LONG};
  type ptr_t[] = {TYPE_PTR};
  struct function funcs[] = {
      {"print", print_types, 1, TYPE_VOID, (void*)print},
      {"print_long_long", pll_t, 1, TYPE_VOID, (void*)print_long_long},
      {"test_ll", pll_t, 1, TYPE_LONG_LONG, (void*)test_ll},
      {"test_ul", pul_t, 1, TYPE_UNSIGNED_LONG, (void*)test_ul},
      {"test_ptr", ptr_t, 1, TYPE_PTR, (void*)test_ptr},
      {"too_big_ptr", ptr_t, 0, TYPE_PTR, (void*)too_big_ptr},
  };


  int result = crossld_start(argv[1], funcs, 6);
  printf("Returned with result %d\n", result);
}
