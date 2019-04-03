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

std::vector<Elf32_Shdr> read_section_headers(const Elf32_Ehdr &header,
                                             std::fstream &file) {
  std::vector<Elf32_Shdr> sections(header.e_shnum);
  if (!file.seekg(header.e_shoff)) {
    perror("Couldn't read sections");
    return {};
  }

  for (int i = 0; i < header.e_shnum; i++) {
    if (!file.read(reinterpret_cast<char *>(&sections[i]),
                   header.e_shentsize)) {
      perror("Couldn't read section header");
      return {};
    }
  }

  return sections;
}

using elf_bytes = std::unique_ptr<const char[]>;

elf_bytes read_section(const Elf32_Shdr &section_header, std::fstream &file) {
  if (section_header.sh_size == 0)
    return {};

  std::unique_ptr<char[]> section(new char[section_header.sh_size]);
  if (!file.seekg(section_header.sh_offset)) {
    perror("Couldn't find section");
    return {};
  }

  if (!file.read(section.get(), section_header.sh_size)) {
    perror("Couldn't read section");
    return {};
  }
  return section;
}

using elf_symbol_table = std::unique_ptr<const Elf32_Sym[]>;
using elf_symbol_strings = std::vector<std::string>;

std::pair<elf_symbol_table, elf_symbol_strings> read_symbol_table(
    const Elf32_Shdr &section_header,
    const Elf32_Shdr &string_header,
    std::fstream &file) {

  //elf_bytes symbol_table_bytes = ;
  std::unique_ptr<const Elf32_Sym[]> symbol_table(
      reinterpret_cast<const Elf32_Sym *>(read_section(section_header,
                                                       file).release()));

  elf_bytes string_table = read_section(string_header, file);
  const auto symbol_count = section_header.sh_size / sizeof(Elf32_Sym);
  std::vector<std::string> symbol_table_strings;
  symbol_table_strings.reserve(symbol_count);

  for (int i = 0; i < symbol_count; i++) {
    symbol_table_strings.push_back(&string_table[symbol_table[i].st_name]);

    printf("0x%08x ", symbol_table[i].st_value);
    printf("0x%02x ", ELF32_ST_BIND(symbol_table[i].st_info));
    printf("0x%02x ", ELF32_ST_TYPE(symbol_table[i].st_info));
    printf("%s\n", (&string_table[symbol_table[i].st_name]));
  }

  return {std::move(symbol_table), std::move(symbol_table_strings)};
}

using elf_rel_table = std::unique_ptr<const Elf32_Rel[]>;

elf_rel_table read_rel_table(const Elf32_Shdr &section_header,
                             std::fstream &file) {
  return elf_rel_table(reinterpret_cast<const Elf32_Rel *>(read_section(
      section_header,
      file).release()));
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
  for (const Elf32_Shdr &section_header : section_headers) {
    std::cout << "Section: " << section_header.sh_size << std::endl;

    if (section_header.sh_type == SHT_DYNSYM) {
      elf_symbol_table symbol_table;
      elf_symbol_strings symbol_table_strings;
      std::tie(symbol_table, symbol_table_strings) = read_symbol_table(
          section_header, section_headers.at(section_header.sh_link), file);

      if (!symbol_table) {
        perror("wtf");
      }

      for (const auto &str: symbol_table_strings) {
        std::cout << str << std::endl;
      }

    } else if (section_header.sh_type == SHT_REL) {// TODO RELA?
      elf_rel_table relocation_table = read_rel_table(section_header, file);


    }


  }

  return 0;
}

