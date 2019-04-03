#include "crossld.h"
#include <elf.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <fstream>
#include <iostream>
#include <vector>

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

std::vector<Elf32_Shdr> read_section_headers(const Elf32_Ehdr &header, std::fstream &file) {
  std::vector<Elf32_Shdr> sections(header.e_shnum);
  if (!file.seekg(header.e_shoff)) {
    perror("Couldn't read sections");
    return {};
  }

  for (int i = 0; i < header.e_shnum; i++) {
    if (!file.read(reinterpret_cast<char*>(&sections[i]), header.e_shentsize)) {
      perror("Couldn't read section header");
      return {};
    }
  }

  return sections;
}

std::vector<char> read_section(const Elf32_Shdr& section_header, std::fstream &file) {
  std::vector<char> section(section_header.sh_size);
  if (!file.seekg(section_header.sh_offset)) {
    perror("Couldn't find section");
    return {};
  }

  if (!file.read(section.data(), section_header.sh_size)) {
    perror("Couldn't read section");
    return {};
  }


}

}



extern "C" int crossld_start(const char *fname,
                             const function *funcs,
                             int nfuncs) {
  std::fstream file(fname, std::ios_base::in | std::ios::binary);

  if (!file) {
    fprintf(stderr, "Couldn't open file [%s]\n", fname);
    return false;
  }

  Elf32_Ehdr header;
  if (!get_header(file, header))
    return -1;

  std::cout << header.e_ident << "\n";
  auto section_headers = read_section_headers(header, file);
  for (const Elf32_Shdr& section_header : section_headers) {

  }


  return 0;
}

