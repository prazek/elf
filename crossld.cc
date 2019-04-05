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

using mapped_exec = std::unique_ptr<char[], Unmapper>;

mapped_exec load_program_segment(const Elf32_Phdr &program_header,
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

  mapped_exec exec(mmaped_ptr, Unmapper{actual_size});

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

void *create_trampoline(const function &func) {
  return nullptr;
}

std::unordered_map<std::string,
                   void *> create_trampolines(const function *funcs,
                                              const int nfuncs) {
  std::unordered_map<std::string, void *> trampolines;
  for (int i = 0; i < nfuncs; i++) {
    trampolines[funcs[i].name] = create_trampoline(funcs[i]);
  }
  return trampolines;
}

std::vector<mapped_exec> alloc_exec(const Elf32_Ehdr &header,
                                    std::fstream &elf_file) {

  const std::vector<Elf32_Phdr>
      program_headers = read_program_headers(header, elf_file);
  std::vector<mapped_exec> mapped_sections;
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
    std::cout << ((void **) relocation.r_offset) << " " << rel_name
              << std::endl;

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

  auto trampolines = create_trampolines(funcs, nfuncs);
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

  return 0;
}

