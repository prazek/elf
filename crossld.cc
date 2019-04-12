#include "crossld.h"
#include "elf_utils.h"
#include "trampolines.h"

#include <elf.h>
#include <sys/mman.h>

#include <unistd.h>

#include <cassert>
#include <csetjmp>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

using namespace elf_utils;

namespace {

bool check_elf(const Elf32_Ehdr& header) {
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0)
    return false;
  if (header.e_type != ET_EXEC)
    return false;
  if (header.e_machine != EM_386)
    return false;
  return true;
}

bool get_header(std::fstream& file, Elf32_Ehdr& header) {
  // read the header
  if (!file.read(reinterpret_cast<char*>(&header), sizeof(header))) {
    fprintf(stderr, "crossld_start: Not long enough elf file");
    return false;
  }

  if (!check_elf(header)) {
    fprintf(stderr, "crossld_start: Unsuported elf file\n");
    return false;
  }
  return true;
}

mmap_utils::mapped_mem load_program_segment(const Elf32_Phdr& program_header, std::fstream& elf_file) {
  int flags = ((program_header.p_flags & PF_W) ? PROT_WRITE : 0) | ((program_header.p_flags & PF_X) ? PROT_EXEC : 0) |
              ((program_header.p_flags & PF_R) ? PROT_READ : 0);
  int flags_before_writing = flags | PROT_WRITE;

  char* mapped_to = (char*)(std::ptrdiff_t)program_header.p_vaddr;
  char* mapped_to_nearest_page = (char*)((std::ptrdiff_t)mapped_to & ~(getpagesize() - 1));
  uint32_t diff = mapped_to - mapped_to_nearest_page;
  uint32_t actual_size = program_header.p_memsz + diff;

  char* mmaped_ptr =
      (char*)mmap(mapped_to_nearest_page, actual_size, flags_before_writing, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  mmap_utils::mapped_mem exec(mmaped_ptr, mmap_utils::Unmapper{actual_size});

  if (exec.get() == MAP_FAILED)
    throw std::system_error(errno, std::system_category(), "crossld_start: Mapping failed");

  if (exec.get() != mapped_to_nearest_page)
    throw std::runtime_error("Required segment to map is already mapped!");

  if (!elf_file.seekg(program_header.p_offset))
    throw std::runtime_error("crossld_start: Can't find segment");

  if (!elf_file.read(exec.get(), program_header.p_filesz))
    throw std::runtime_error("crossld_start: Couldn't read segment");

  if (flags_before_writing != flags) {
    if (mprotect(mapped_to, program_header.p_memsz, flags) != 0) {
      throw std::system_error(errno, std::system_category(), "Failed to protect mapped region");
    }
  }
  return exec;
}

std::vector<mmap_utils::mapped_mem> alloc_exec(const Elf32_Ehdr& header, std::fstream& elf_file) {
  const std::vector<Elf32_Phdr> program_headers = read_program_headers(header, elf_file);
  std::vector<mmap_utils::mapped_mem> mapped_sections;
  mapped_sections.reserve(program_headers.size());

  for (const Elf32_Phdr& pheader : program_headers) {
    // Skip
    if (pheader.p_type != PT_LOAD)
      continue;
    if (pheader.p_filesz > pheader.p_memsz)
      throw std::runtime_error("Can't load segment into memory. Segment file size > memory size");
    if (pheader.p_filesz == 0)
      continue;

    mapped_sections.push_back(load_program_segment(pheader, elf_file));
  }
  return mapped_sections;
}

void set_rellocations(const elf_symbol_strings& symbol_table_strings, const elf_rel_table& relocation_table,
                      const std::unordered_map<std::string, void*>& trampolines) {
  for (const Elf32_Rel& relocation : relocation_table) {
    const std::string& rel_name = symbol_table_strings[ELF32_R_SYM(relocation.r_info)];
    auto trampoline_code = trampolines.find(rel_name);
    if (trampoline_code == trampolines.end())
      throw std::runtime_error(std::string("Function [") + rel_name + "] not provided");

    char* address_to_substitute = (char*)(std::ptrdiff_t)relocation.r_offset;
    std::memcpy(address_to_substitute, &trampoline_code->second, 4);
  }
}

}  // namespace

extern "C" int crossld_start(const char* fname, const function* funcs, int nfuncs) try {
  std::fstream elf_file(fname, std::ios_base::in | std::ios::binary);

  if (!elf_file)
    throw std::runtime_error(std::string("Couldn't open elf file [") + fname + "]");

  Elf32_Ehdr header;
  if (!get_header(elf_file, header))
    return -1;

  std::vector<mmap_utils::mapped_mem> alloced_trampolines;

  auto trampolines = trampolines::create_trampolines(funcs, nfuncs, alloced_trampolines);
  auto mapped_segments = alloc_exec(header, elf_file);

  auto section_headers = read_section_headers(header, elf_file);

  elf_symbol_table symbol_table;
  elf_symbol_strings symbol_table_strings;
  elf_rel_table relocation_table;

  for (const Elf32_Shdr& section_header : section_headers) {
    if (section_header.sh_type == SHT_DYNSYM) {
      std::tie(symbol_table, symbol_table_strings) =
          read_symbol_table(section_header, section_headers.at(section_header.sh_link), elf_file);

    } else if (section_header.sh_type == SHT_REL) {
      relocation_table = read_rel_table(section_header, elf_file);
    }
  }

  set_rellocations(symbol_table_strings, relocation_table, trampolines);

  static const int STACK_SIZE = 1024 * 1024 * 4;  // 4MB of stack.
  void* stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
  if (stack == MAP_FAILED)
    throw std::system_error(errno, std::system_category(), "Can't allocate stack");

  const void* reversed_stack = (void*)(((uint64_t)stack) + STACK_SIZE - 4);
  char* entry_point = (char*)(std::ptrdiff_t)header.e_entry;

  if (setjmp(trampolines::get_exit_jump_buffer()) == 0) {
    /* Switch to 32-bit mode and jump into the 32-bit code */
    __asm__ volatile(
        "movq %0, %%rsp  \n"
        "subq $8, %%rsp \n"
        "movl $0x23, 4(%%rsp) \n"
        "movl %k1, (%%rsp) \n"
        "movw %w2, %%ds \n"
        "movw %w2, %%es \n"
        "lret" ::"irm"(reversed_stack),
        "r"(entry_point), "r"(0x2b)
        : "rax", "memory", "flags");
    assert(false && "This asm does not return, we get back only through longjmp");
  }

  return trampolines::get_exit_code();
} catch (std::system_error& err) {
  fprintf(stderr, "Error crossld_start: %s : %s\n", err.what(), std::strerror(err.code().value()));
  return -1;
} catch (std::exception& ex) {
  fprintf(stderr, "Error crossld_start: %s\n", ex.what());
  return -1;
}
