#include "crossld.h"
#include "elf_utils.h"

#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <cassert>

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
    perror("Not long enough elf file");
    return false;
  }

  if (!check_elf(header)) {
    perror("Unsuported elf file");
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

  printf("mapping region [0x%lx, 0x%lx]\n",
         (uint64_t) mapped_to_nearest_page,
         (uint64_t) mapped_to + actual_size);

  char *mmaped_ptr = (char *) mmap(mapped_to_nearest_page,
                                   actual_size,
                                   flags_before_writing,
                                   MAP_ANONYMOUS | MAP_PRIVATE,
                                   -1,
                                   0); // TODO check MAP_PRIVATE

  mapped_mem exec(mmaped_ptr, Unmapper{actual_size});

  if (exec.get() == MAP_FAILED) {
    perror("Mapping failed");
    return {};
  }
  if (exec.get() != mapped_to_nearest_page) {
    fprintf(stderr, "Required segment to map is already mapped!\n");
    return {};
  }

  if (!elf_file.seekg(program_header.p_offset)) {
    perror("Can't find segment\n");
    return {};
  }
  std::cout << "After mapping" << std::endl;

  if (!elf_file.read(exec.get(), program_header.p_filesz)) {
    perror("Couldn't read segment\n");
    return {};
  }
  std::cout << "Loaded segment at address " << program_header.p_vaddr
            << std::endl;

  if (flags_before_writing != flags) {
    if (mprotect(mapped_to, program_header.p_memsz, flags) != 0) {
      perror("Failed to protect mapped region\n");
      return {};
    }
  }
  return exec;
}



int set_register(int arg_num, type arg_type, char *code) {
  if (arg_type == type::TYPE_LONG_LONG || arg_type == type::TYPE_UNSIGNED_LONG_LONG) {
    switch(arg_num) {
      case 0:
        *code = 0x5f; // pop rdi
        return 1;
      case 1:
        *code = 0x5e; // pop rsi
        return 1;
    default:
      printf("TODO: Not supported\n");
    }
  } else {
    printf("TODO: also not supported yet\n");
  }
  return 0;
}

void set_registers(const function &func, char*& code) {
  for (int arg_num = 0; arg_num < func.nargs; arg_num++) {
    int diff = set_register(arg_num, func.args[arg_num], code);
    code += diff;
  }

}

// This code switches to 64 bit mode and continue executing next 64bits instructions.
const unsigned char TRAMPOLINE_SWITCH_TO_64_BITS[] = {
    0x6a, 0x33,               // 0: push   $0x33
    0x68, 00, 00, 00, 00,     // 2: push   $0x0
    0xcb                      // 7: lret
};

const unsigned char CALL_FN[] = {
    0xe8, 0, 0, 0, 0   // call <PUT_ADDR_HERE>
};


void *create_trampoline(const function &func, char *&code, char *code_end) {
  char *begin_of_function = code;
  assert(code_end - code > 100); // TODO

  memcpy(code, TRAMPOLINE_SWITCH_TO_64_BITS, sizeof(TRAMPOLINE_SWITCH_TO_64_BITS));
  code += sizeof(TRAMPOLINE_SWITCH_TO_64_BITS);

  set_registers(func, code);

  memcpy(code, CALL_FN, sizeof(CALL_FN));
  int32_t function_offset = (char*)func.code - code;
  // Put address of real function
  memcpy(code + 1, &function_offset, 4);
  code += sizeof(CALL_FN);




  return begin_of_function;
}

void *create_exit_trampoline() {
  return nullptr; // TODO
}

std::unordered_map<std::string, void *> create_trampolines(const function *funcs,
                                                           const int nfuncs,
                                                           std::vector<mapped_mem> &alloced_trampolines) {

  static const int TRAMPOLINES_BUFFER = 4 * 1024;
  auto alloc_trampolines_code = []() {

    char *memory = (char *) mmap(NULL, TRAMPOLINES_BUFFER, PROT_EXEC | PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
      perror("Can't allocate memory for trampolines");
      return mapped_mem{};
    }
    return mapped_mem(memory, Unmapper{TRAMPOLINES_BUFFER});
  };
  
  alloced_trampolines.push_back(alloc_trampolines_code());
  char* trampolines_begin = alloced_trampolines.back().get();
  char* trampolines_end = trampolines_begin + TRAMPOLINES_BUFFER;
  

  std::unordered_map<std::string, void *> trampolines;
  for (int i = 0; i < nfuncs; i++) {
    trampolines[funcs[i].name] = create_trampoline(funcs[i], trampolines_begin, trampolines_end);
  }
  
  if (trampolines.count("exit"))
    trampolines["exit"] = create_exit_trampoline();

  return trampolines;
}

std::vector<mapped_mem> alloc_exec(const Elf32_Ehdr &header,
                                    std::fstream &elf_file) {

  const std::vector<Elf32_Phdr>
      program_headers = read_program_headers(header, elf_file);
  std::vector<mapped_mem> mapped_sections;
  mapped_sections.reserve(program_headers.size());

  for (const Elf32_Phdr &pheader : program_headers) {
    std::cout << "Program header " << pheader.p_type << " " << std::ios::hex
              << pheader.p_offset << " " << pheader.p_vaddr << "\n";
    // Skip
    if (pheader.p_type != PT_LOAD)
      continue;
    std::cout << "loadable\n";
    if (pheader.p_filesz > pheader.p_memsz) {
      perror("TODO: Check this");
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

  std::cout << "relocations\n";
  for (const Elf32_Rel &relocation : relocation_table) {

    const std::string
        &rel_name = symbol_table_strings[ELF32_R_SYM(relocation.r_info)];
    auto trampoline_code = trampolines.find(rel_name);
    if (trampoline_code == trampolines.end())
      continue;

    *((void **) (ptrdiff_t) relocation.r_offset) = trampoline_code->second;
  }

}

}

extern "C" int crossld_start(const char *fname,
                             const function *funcs,
                             int nfuncs) {
  std::fstream elf_file(fname, std::ios_base::in | std::ios::binary);

  if (!elf_file) {
    fprintf(stderr, "Couldn't open file [%s]\n", fname);
    return false;
  }

  Elf32_Ehdr header;
  if (!get_header(elf_file, header))
    return -1;

  std::vector<mapped_mem> alloced_trampolines;

  auto trampolines = create_trampolines(funcs, nfuncs, alloced_trampolines);
  auto mapped_segments = alloc_exec(header, elf_file);

  std::cout << header.e_ident << "\n";
  auto section_headers = read_section_headers(header, elf_file);

  elf_symbol_table symbol_table;
  elf_symbol_strings symbol_table_strings;
  elf_rel_table relocation_table;

  for (const Elf32_Shdr &section_header : section_headers) {
    std::cout << "Section: " << section_header.sh_size << std::endl;

    if (section_header.sh_type == SHT_DYNSYM) {
      std::tie(symbol_table, symbol_table_strings) = read_symbol_table(
          section_header, section_headers.at(section_header.sh_link), elf_file);

      for (const auto &str: symbol_table_strings) {
        std::cout << str << std::endl;
      }

    } else if (section_header.sh_type == SHT_REL) {// TODO RELA?
      std::cout << "found REL";
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
    perror("Can't allocate stack\n");
    return -1;
  }

  const void* reversed_stack =  (void*) (((uint64_t) stack) + STACK_SIZE - 4);

  char* entry_point = (char*)(ptrdiff_t)header.e_entry;


  /* Switch to 32-bit mode and jump into the 32-bit code */
  __asm__ volatile("movq %0, %%rsp;\n"
                   "subq $8, %%rsp\n"
                   "movl $0x23, 4(%%rsp);\n"
                   "movq %1, %%rax;\n"
                   "movl %%eax, (%%rsp);\n"
                   "lret" ::  "r"(reversed_stack), "r"(entry_point) );


  return 0;
}

