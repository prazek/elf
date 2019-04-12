#pragma once

#include <csetjmp>
#include "crossld.h"
#include "mmap_utils.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace trampolines {

jmp_buf& get_exit_jump_buffer();
int get_exit_code();

void* create_trampoline(const function& func, char*& code, char* code_end);

std::unordered_map<std::string, void*> create_trampolines(const function* funcs, const int nfuncs,
                                                          std::vector<mmap_utils::mapped_mem>& alloced_trampolines);

}  // namespace trampolines
