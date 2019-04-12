#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum type {
  TYPE_VOID,
  TYPE_INT,
  TYPE_LONG,
  TYPE_LONG_LONG,
  TYPE_UNSIGNED_INT,
  TYPE_UNSIGNED_LONG,
  TYPE_UNSIGNED_LONG_LONG,
  TYPE_PTR,
};

struct function {
  const char *name;
  const enum type *args;
  int nargs;
  enum type result;
  void *code;
};


/*
 * While executing x86_64 code, start Elf32 executable [fname] with provided
 * functions.
 * For each function it creates a trampoline that:
 * 1. from 32 bit mode switches to 64 bit mode
 * 2. moves arguments to right registers for the x64 calling convention
 * 3. executes given function
 * 4. checks if returned value fits into return type, if not finished execution
 *    with code -1
 * 5. switches to 32 bit mode
 * 6. returns to 32 bit exec
 *
 * It then set all the relocations of the given executable.
 * For now, only REL is supported.
 *
 * In the end, it returns the code for the execution.
 */
int crossld_start(const char *fname, const struct function *funcs, int nfuncs);

#ifdef __cplusplus
}
#endif