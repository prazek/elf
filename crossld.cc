#include "crossld.h"
#include "elf_utils.h"

#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <csetjmp>

using namespace elf_utils;

namespace {
bool check_elf(const Elf32_Ehdr &header) {
  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0)
    return false;
  if (header.e_type != ET_EXEC)
    return false;
  if (header.e_machine != EM_386)
    return false;
  return true;
}

bool get_header(std::fstream &file, Elf32_Ehdr &header) {
  // read the header
  if (!file.read(reinterpret_cast<char *>(&header), sizeof(header))) {
    fprintf(stderr, "crossld_start: Not long enough elf file");
    return false;
  }

  if (!check_elf(header)) {
    fprintf(stderr, "crossld_start: Unsuported elf file\n");
    return false;
  }
  return true;
}

struct Unmapper {
  uint32_t prog_size;

  void operator()(char *ptr) const { munmap(ptr, prog_size); }
};

using mapped_mem = std::unique_ptr<char[], Unmapper>;

mapped_mem load_program_segment(const Elf32_Phdr &program_header,
                                std::fstream &elf_file) {

  int flags = ((program_header.p_flags & PF_W) ? PROT_WRITE : 0) |
      ((program_header.p_flags & PF_X) ? PROT_EXEC : 0) |
      ((program_header.p_flags & PF_R) ? PROT_READ : 0);
  int flags_before_writing = flags | PROT_WRITE;

  char *mapped_to = (char *) (ptrdiff_t) program_header.p_vaddr;
  char *mapped_to_nearest_page =
      (char *) ((ptrdiff_t) mapped_to & ~(getpagesize() - 1));
  uint32_t diff = mapped_to - mapped_to_nearest_page;
  uint32_t actual_size = program_header.p_memsz + diff;

  char *mmaped_ptr = (char *) mmap(mapped_to_nearest_page,
                                   actual_size,
                                   flags_before_writing,
                                   MAP_ANONYMOUS | MAP_PRIVATE,
                                   -1,
                                   0); // TODO check MAP_PRIVATE

  mapped_mem exec(mmaped_ptr, Unmapper{actual_size});

  if (exec.get() == MAP_FAILED) {
    perror("crossld_start: Mapping failed");
    return {};
  }
  if (exec.get() != mapped_to_nearest_page) {
    fprintf(stderr, "crossld_start: Required segment to map is already mapped!\n");
    return {};
  }

  if (!elf_file.seekg(program_header.p_offset)) {
    fprintf(stderr, "crossld_start: Can't find segment\n");
    return {};
  }

  if (!elf_file.read(exec.get(), program_header.p_filesz)) {
    fprintf(stderr, "crossld_start: Couldn't read segment\n");
    return {};
  }

  if (flags_before_writing != flags) {
    if (mprotect(mapped_to, program_header.p_memsz, flags) != 0) {
      perror("crossld_start: Failed to protect mapped region\n");
      return {};
    }
  }
  return exec;
}

constexpr int NUM_REGISTERS = 6;
unsigned char CONV_64_TO_64_OPCODES[NUM_REGISTERS][4] = {
    {0x48, 0x8b, 0x3c, 0x24},  // mov    (%rsp),%rdi
    {0x48, 0x8b, 0x34, 0x24},  // mov    (%rsp),%rsi
    {0x48, 0x8b, 0x14, 0x24},  // mov    (%rsp),%rdx
    {0x48, 0x8b, 0x0c, 0x24},  // mov    (%rsp),%rcx
    {0x4c, 0x8b, 0x0c, 0x24},  // mov    (%rsp),%r9
    {0x4c, 0x8b, 0x04, 0x24}   // mov    (%rsp),%r8
};

unsigned char SHRINK_STACK_UP_TO_256_BYTES[] {
    0x48, 0x83, 0xc4, 00  // add    VALUE, %rsp
};

unsigned char GROW_STACK_UP_TO_256_BYTES[] {
    0x48, 0x83, 0xec, 00  // sub    VALUE, %rsp
};

unsigned char CONV_32_BIT_OPCODES_SHORT[4][3] = {
    {0x8b, 0x3c, 0x24},    //  mov    (%rsp),%edi
    {0x8b, 0x34, 0x24},    //  mov    (%rsp),%esi
    {0x8b, 0x14, 0x24},    //  mov    (%rsp),%edx
    {0x8b, 0x0c, 0x24}     //  mov    (%rsp),%ecx
};

unsigned char CONV_32_BIT_OPCODES_LONGER[2][4] = {
    {0x44, 0x8b, 0x0c, 0x24},   //  mov    (%rsp),%r9d
    {0x44, 0x8b, 0x04, 0x24}    //  mov    (%rsp),%r8d
};

unsigned char CONV_SIGNED_32_BIT_TO_SIGNED_64[NUM_REGISTERS][4] = {
    {0x48, 0x63, 0x3c, 0x24}, //  movslq (%rsp),%rdi
    {0x48, 0x63, 0x34, 0x24}, //  movslq (%rsp),%rsi
    {0x48, 0x63, 0x14, 0x24}, //  movslq (%rsp),%rdx
    {0x48, 0x63, 0x0c, 0x24}, //  movslq (%rsp),%rcx
    {0x4c, 0x63, 0x0c, 0x24}, //  movslq (%rsp),%r9
    {0x4c, 0x63, 0x04, 0x24}  //  movslq (%rsp),%r8
};
int grow_stack(int bytes_num, char* code) {
  assert(bytes_num < 256);
  memcpy(code, GROW_STACK_UP_TO_256_BYTES, sizeof(GROW_STACK_UP_TO_256_BYTES));
  unsigned char bytes_num_c = (char)bytes_num;
  code[3] = bytes_num_c;
  return sizeof(GROW_STACK_UP_TO_256_BYTES);
}
int shrink_stack(int bytes_num, char *code) {
  assert(bytes_num < 256);
  memcpy(code, SHRINK_STACK_UP_TO_256_BYTES, sizeof(SHRINK_STACK_UP_TO_256_BYTES));
  unsigned char bytes_num_c = (char)bytes_num;
  code[3] = bytes_num_c;
  return sizeof(SHRINK_STACK_UP_TO_256_BYTES);
}

int set_register(unsigned arg_num, type arg_type, int &stack_shrank, char *code) {
  switch (arg_type) {
  case type::TYPE_LONG_LONG:
  case type::TYPE_UNSIGNED_LONG_LONG:
    if (arg_num < NUM_REGISTERS) {
      memcpy(code, CONV_64_TO_64_OPCODES[arg_num], 4);
      stack_shrank += 8;
      return 4 + shrink_stack(8, code + 4);
    }
    printf("TODO: not supported\n");
    return 0;
  case type::TYPE_PTR:
  case type::TYPE_UNSIGNED_LONG:
  case type::TYPE_INT:
  case type::TYPE_UNSIGNED_INT:
    if (arg_num < 4) {
      memcpy(code, CONV_32_BIT_OPCODES_SHORT[arg_num], 3);
      stack_shrank += 4;
      return 3 + shrink_stack(4, code + 3);
    }
    if (arg_num < 6) {
      memcpy(code, CONV_32_BIT_OPCODES_LONGER[arg_num - 4], 4);
      stack_shrank += 4;
      return 4 + shrink_stack(4, code + 4);
    }
    printf("TODO: not supported\n");
    return 0;
  case type::TYPE_LONG:
    if (arg_num < NUM_REGISTERS) {
      memcpy(code, CONV_SIGNED_32_BIT_TO_SIGNED_64[arg_num], 4);
      stack_shrank += 4;
      return 4 + shrink_stack(4, code + 4);
    }
    printf("TODO not supported\n");
  case type::TYPE_VOID:
    printf("Arg can't be void\n");
  }

  return 0;
}


void set_registers(const function &func, char *&code) {
  int stack_shrank = 0;
  for (int arg_num = 0; arg_num < func.nargs; arg_num++) {
    int diff = set_register(arg_num, func.args[arg_num], stack_shrank, code);
    code += diff;
  }

  code += grow_stack(stack_shrank, code);
}

static int exit_code = 0;
jmp_buf exit_buff;
__attribute__((noreturn)) void exit_64bit(int code) {
  exit_code = code;
  longjmp(exit_buff, 1);
}

// This code switches to 64 bit mode and continue executing next 64bits instructions.
const unsigned char TRAMPOLINE_SWITCH_TO_64_BITS[] = {
    0x6a, 0x33,               // 0: push   $0x33
    0x68, 00, 00, 00, 00,     // 2: push   $0x0
    0xcb                      // 7: lret
};

// In 32 bit calling convention edi and esi registers do not change when calling function,
// which means we need to save them, as 64 bit code does not have this requirement.
const unsigned char SAVE_EDI_AND_ESI[] = {
    0x41, 0x89, 0xfe,  //   mov    %edi,%r14d
    0x41, 0x89, 0xf7   //   mov    %esi,%r15d

};

const unsigned char SAVE_RETURN_PTR[] = {
    0x44, 0x8b, 0x2c, 0x24,   //  mov    (%rsp),%r13d
    0x48, 0x83, 0xc4, 0x04    //  add    $0x4,%rsp
};

// Before call, we need to fix aslignment of stack.
const unsigned char FIX_ALIGNMENT_OF_STACK[] = {
    0x49, 0x89, 0xe4,         // mov    %rsp,%r12
    0x48, 0x83, 0xe4, 0xf0    // and    $0xfffffffffffffff0,%rsp

};

const unsigned char CALL_FN[] = {
    0xe8, 0, 0, 0, 0   // call <PUT_ADDR_HERE>
};

const unsigned SIGNED_LONG_EXIT_OFFSET = 22;
const unsigned char CHECK_RETURNED_SIGNED_LONG[] = {
    0xba, 0x00, 0x00, 0x00, 0x80, //  mov    $0x80000000,%edx
    0xb9, 0xff, 0xff, 0xff, 0xff, //  mov    $0xffffffff,%ecx
    0x48, 0x01, 0xc2,             //  add    %rax,%rdx
    0x48, 0x39, 0xca,             //  cmp    %rcx,%rdx
    0x76, 0x1a,                   // jbe    b3 <ok>
    0x83, 0xcf, 0xff,             //  or     $0xffffffff,%edi
    0xe8, 00, 00, 00, 00          // callq  c7 <exit_64bit>
};

const unsigned UNSIGNED_LONG_EXIT_ADDR_OFFSET = 14;
const unsigned char CHECK_RETURNED_UNSIGNED_LONG_OR_PTR[] = {
    0xb9, 0xff, 0xff, 0xff, 0xff, // mov    $0xffffffff,%ecx
    0x48, 0x39, 0xc8,             // cmp    %rcx,%rax
    0x76, 0x08,                   // jbe    b3 <ok>
    0x83, 0xcf, 0xff,             // or     $0xffffffff,%edi
    0xe8, 00, 00, 00, 00          // callq  c7 <exit_64bit>
};

const unsigned char MOVE_UPPER_BITS_TO_EDX[] = {
    0x48, 0x89, 0xc2,             // mov    %rax,%rdx
    0x48, 0xc1, 0xea, 0x20        // shr    $0x20,%rdx
};

const unsigned char REMOVE_ALIGNMENT_OF_STACK[] = {
    0x4c, 0x89, 0xe4   // mov    %r12,%rsp
};

const unsigned char RESTORE_EDI_AND_ESI[] = {
    0x44, 0x89, 0xf7,   // mov    %r14d,%edi
    0x44, 0x89, 0xfe    // mov    %r15d,%esi
};

const unsigned char FIX_RETURN_PTR[] = {
    0x48, 0x83, 0xec, 0x04,   //  sub    $0x4,%rsp
    0x44, 0x89, 0x2c, 0x24    //  mov    %r13d,(%rsp)
};

const int RETURN_TO_32_BITS_ADDR_INDX = 15;
const unsigned char RETURN_TO_32_BITS[] = {
    0x48, 0x83, 0xec, 0x08,                         // sub    $0x8,%rsp
    0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // movl   $0x23,0x4(%rsp)
    0xc7, 0x04, 0x24, 00, 00, 00, 00,               // movl   <PUT_ADDR_HERE>,(%rsp)
    0xcb                                            // lret
};

const unsigned char SET_32_BITS_SEGMENTS[] = {
    0x6a, 0x2b,              // push   $0x2b
    0x1f,                    // pop    %ds
    0x6a, 0x2b,              // push   $0x2b
    0x07                     // pop    %es
};

const unsigned char RETURN_FROM_TRAMPOLINE[] = {
   0xc3, // ret
};

int32_t get_relative_fn_addr(void* fn_addr, char *place_for_addr) {
  return (char *) fn_addr - (place_for_addr + 4);
}

void set_returned_value(type return_type, char *&code) {
  // If returned value is 64 bit signed long, we need to check if it fits
  // 32 bit long.
  if (return_type == TYPE_LONG) {
    memcpy(code, CHECK_RETURNED_SIGNED_LONG, sizeof(CHECK_RETURNED_SIGNED_LONG));
    int32_t exit_relative_addr = get_relative_fn_addr((void*)exit_64bit, code + SIGNED_LONG_EXIT_OFFSET);
    memcpy(code + SIGNED_LONG_EXIT_OFFSET, &exit_relative_addr, 4);
    code += sizeof(CHECK_RETURNED_SIGNED_LONG);
    return;
  }
  // Similarly, if value is 64 bit ptr or 64 bit unsigned long we need to check if it fits
  // 32 bits.
  if (return_type == TYPE_UNSIGNED_LONG || return_type == TYPE_PTR) {
    memcpy(code, CHECK_RETURNED_UNSIGNED_LONG_OR_PTR, sizeof(CHECK_RETURNED_UNSIGNED_LONG_OR_PTR));
    int32_t exit_relative_addr = get_relative_fn_addr((void*)exit_64bit, code + UNSIGNED_LONG_EXIT_ADDR_OFFSET);
    memcpy(code + UNSIGNED_LONG_EXIT_ADDR_OFFSET, &exit_relative_addr, 4);
    code += sizeof(CHECK_RETURNED_UNSIGNED_LONG_OR_PTR);
    return;
  }
  // move 64 bit return value from rax to edx:eax
  if (return_type == TYPE_UNSIGNED_LONG_LONG || return_type == TYPE_LONG_LONG) {
    memcpy(code, MOVE_UPPER_BITS_TO_EDX, sizeof(MOVE_UPPER_BITS_TO_EDX));
    code += sizeof(MOVE_UPPER_BITS_TO_EDX);
    return;
  }
}


void *create_trampoline(const function &func, char *&code, char *code_end) {
  char *begin_of_function = code;
  assert(code_end - code > 100); // TODO

  memcpy(code, TRAMPOLINE_SWITCH_TO_64_BITS, sizeof(TRAMPOLINE_SWITCH_TO_64_BITS));
  char *addr_aftertrampoline = code + sizeof(TRAMPOLINE_SWITCH_TO_64_BITS);
  memcpy(code + 3, &addr_aftertrampoline, 4);
  code += sizeof(TRAMPOLINE_SWITCH_TO_64_BITS);

  memcpy(code, SAVE_EDI_AND_ESI, sizeof(SAVE_EDI_AND_ESI));
  code += sizeof(SAVE_EDI_AND_ESI);

  memcpy(code, SAVE_RETURN_PTR, sizeof(SAVE_RETURN_PTR));
  code += sizeof(SAVE_RETURN_PTR);

  set_registers(func, code);

  memcpy(code, FIX_ALIGNMENT_OF_STACK, sizeof(FIX_ALIGNMENT_OF_STACK));
  code += sizeof(FIX_ALIGNMENT_OF_STACK);

  memcpy(code, CALL_FN, sizeof(CALL_FN));
  int32_t function_offset = get_relative_fn_addr(func.code, code + 1);
  // Put address of real function
  memcpy(code + 1, &function_offset, 4);
  code += sizeof(CALL_FN);

  set_returned_value(func.result, code);

  memcpy(code, REMOVE_ALIGNMENT_OF_STACK, sizeof(REMOVE_ALIGNMENT_OF_STACK));
  code += sizeof(REMOVE_ALIGNMENT_OF_STACK);

  memcpy(code, RESTORE_EDI_AND_ESI, sizeof(RESTORE_EDI_AND_ESI));
  code += sizeof(RESTORE_EDI_AND_ESI);

  memcpy(code, FIX_RETURN_PTR, sizeof(FIX_RETURN_PTR));
  code += sizeof(FIX_RETURN_PTR);


  memcpy(code, RETURN_TO_32_BITS, sizeof(RETURN_TO_32_BITS));
  char *addr_after_returning_to_32_bit = code + sizeof(RETURN_TO_32_BITS);
  memcpy(code + RETURN_TO_32_BITS_ADDR_INDX, &addr_after_returning_to_32_bit, 4);
  code += sizeof(RETURN_TO_32_BITS);

  memcpy(code, SET_32_BITS_SEGMENTS, sizeof(SET_32_BITS_SEGMENTS));
  code += sizeof(SET_32_BITS_SEGMENTS);

  memcpy(code, RETURN_FROM_TRAMPOLINE, sizeof(RETURN_FROM_TRAMPOLINE));
  code += sizeof(RETURN_FROM_TRAMPOLINE);

  return begin_of_function;
}

std::unordered_map<std::string, void *> create_trampolines(const function *funcs,
                                                           const int nfuncs,
                                                           std::vector<mapped_mem> &alloced_trampolines) {

  static const int TRAMPOLINES_BUFFER = 4 * 1024;
  auto alloc_trampolines_code = []() {

    char *memory = (char *) mmap(NULL, TRAMPOLINES_BUFFER, PROT_EXEC | PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (memory == MAP_FAILED) {
      perror("Can't allocate memory for trampolines");
      return mapped_mem{};
    }
    return mapped_mem(memory, Unmapper{TRAMPOLINES_BUFFER});
  };

  alloced_trampolines.push_back(alloc_trampolines_code());
  char *trampolines_begin = alloced_trampolines.back().get();
  char *trampolines_end = trampolines_begin + TRAMPOLINES_BUFFER;

  std::unordered_map<std::string, void *> trampolines;
  for (int i = 0; i < nfuncs; i++) {
    trampolines[funcs[i].name] = create_trampoline(funcs[i], trampolines_begin, trampolines_end);
  }

  // Additionaly, we add trampoline for the exit function.
  enum type exit_types[] = {TYPE_INT};
  struct function exit_func =
      {"exit", exit_types, 1, TYPE_VOID, (void*)exit_64bit};
  trampolines["exit"] = create_trampoline(exit_func, trampolines_begin, trampolines_end);

  return trampolines;
}

std::vector<mapped_mem> alloc_exec(const Elf32_Ehdr &header,
                                   std::fstream &elf_file) {
  const std::vector<Elf32_Phdr>
      program_headers = read_program_headers(header, elf_file);
  std::vector<mapped_mem> mapped_sections;
  mapped_sections.reserve(program_headers.size());

  for (const Elf32_Phdr &pheader : program_headers) {
    // Skip
    if (pheader.p_type != PT_LOAD)
      continue;
    if (pheader.p_filesz > pheader.p_memsz) {
      fprintf(stderr, "Can't load segment into memory\n");
      return {};
    }
    if (pheader.p_filesz == 0)
      continue;

    mapped_sections.push_back(load_program_segment(pheader, elf_file));
  }
  return mapped_sections;
}

void set_rellocations(
    const elf_symbol_strings &symbol_table_strings,
    const elf_rel_table &relocation_table,
    const std::unordered_map<std::string, void *> &trampolines) {

  for (const Elf32_Rel &relocation : relocation_table) {
    const std::string
        &rel_name = symbol_table_strings[ELF32_R_SYM(relocation.r_info)];
    auto trampoline_code = trampolines.find(rel_name);
    if (trampoline_code == trampolines.end())
      continue;

    char *address_to_substitute = (char *) (ptrdiff_t) relocation.r_offset;
    memcpy(address_to_substitute, &trampoline_code->second, 4);
  }
}

}

extern "C" int crossld_start(const char *fname,
                             const function *funcs,
                             int nfuncs) {
  std::fstream elf_file(fname, std::ios_base::in | std::ios::binary);

  if (!elf_file) {
    fprintf(stderr, "crossld_start: Couldn't open file [%s]\n", fname);
    return false;
  }

  Elf32_Ehdr header;
  if (!get_header(elf_file, header))
    return -1;

  std::vector<mapped_mem> alloced_trampolines;

  auto trampolines = create_trampolines(funcs, nfuncs, alloced_trampolines);
  auto mapped_segments = alloc_exec(header, elf_file);

  auto section_headers = read_section_headers(header, elf_file);

  elf_symbol_table symbol_table;
  elf_symbol_strings symbol_table_strings;
  elf_rel_table relocation_table;

  for (const Elf32_Shdr &section_header : section_headers) {

    if (section_header.sh_type == SHT_DYNSYM) {
      std::tie(symbol_table, symbol_table_strings) = read_symbol_table(
          section_header, section_headers.at(section_header.sh_link), elf_file);

    } else if (section_header.sh_type == SHT_REL) {
      relocation_table = read_rel_table(section_header, elf_file);
    }
  }

  set_rellocations(symbol_table_strings, relocation_table, trampolines);

  static const int STACK_SIZE = 1024 * 1024 * 4; // 4MB of stack.
  void *stack = mmap(NULL,
                     STACK_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT,
                     -1,
                     0);
  if (stack == MAP_FAILED) {
    perror("crossld_start: Can't allocate stack\n");
    return -1;
  }

  const void *reversed_stack = (void *) (((uint64_t) stack) + STACK_SIZE - 4);
  char *entry_point = (char *) (ptrdiff_t) header.e_entry;

  if (setjmp(exit_buff) == 0) {
    /* Switch to 32-bit mode and jump into the 32-bit code */
    __asm__ volatile("movq %0, %%rsp  \n"
                     "subq $8, %%rsp \n"
                     "movl $0x23, 4(%%rsp) \n"
                     "movq %1, %%rax \n"
                     "movl %%eax, (%%rsp) \n"
                     "movw %w2, %%ds \n"
                     "movw %w2, %%es \n"
                     "lret"::"irm"(reversed_stack), "r"(entry_point), "r"(0x2b)
    : "rax", "memory", "flags");
    assert(false && "This asm does not return, we get back only through longjmp");
  }

  return exit_code;
}

