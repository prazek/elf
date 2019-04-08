#include <elf.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "crossld.h"

static void print(char *c) {
  printf("Also maybe this will work?\n");
  fprintf(stderr, "From 64bit code: [%s]\n", c);
}

int main(int argc, char *argv[]) {
  if (argc < 2)
    exit(2);


  enum type print_types[] = {TYPE_PTR};
  struct function funcs[] = {
      {"print", print_types, 1, TYPE_VOID, (void*)print},
  };


  crossld_start(argv[1], funcs, 1);
}
