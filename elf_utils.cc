#include "elf_utils.h"

namespace elf_utils {

std::vector<Elf32_Shdr> read_section_headers(const Elf32_Ehdr &header,
                                             std::fstream &file) {
  std::vector<Elf32_Shdr> sections(header.e_shnum);
  if (!file.seekg(header.e_shoff))
    throw std::runtime_error("Empty elf header");

  for (int i = 0; i < header.e_shnum; i++) {
    if (!file.read(reinterpret_cast<char *>(&sections[i]),
                   header.e_shentsize))
      throw std::runtime_error("Couldn't read section header");
  }

  return sections;
}

using elf_bytes = std::unique_ptr<const char[]>;

elf_bytes read_section(const Elf32_Shdr &section_header, std::fstream &file) {
  if (section_header.sh_size == 0)
    throw std::runtime_error("Empty elf header");

  std::unique_ptr<char[]> section(new char[section_header.sh_size]);
  if (!file.seekg(section_header.sh_offset))
    throw std::runtime_error("Could not find elf section");

  if (!file.read(section.get(), section_header.sh_size))
    throw std::runtime_error("Could not read elf section");

  return section;
}

using elf_symbol_table = std::vector<Elf32_Sym>;
using elf_symbol_strings = std::vector<std::string>;

std::tuple<elf_symbol_table, elf_symbol_strings>
read_symbol_table(const Elf32_Shdr &section_header,
                  const Elf32_Shdr &string_header, std::fstream &file) {

  const auto symbol_count = section_header.sh_size / sizeof(Elf32_Sym);

  std::vector<Elf32_Sym> symbol_table = [&] {
    elf_bytes symbol_table_bytes = read_section(section_header, file);
    // In C++20 we would bless the memory so that we would not have to call
    // memcopy, but since we do not use strict-aliasing, it is fine.
    const auto *begin =
        reinterpret_cast<const Elf32_Sym *>(symbol_table_bytes.get());
    const auto *end = begin + symbol_count;
    return elf_symbol_table(begin, end);
  }();

  elf_bytes string_table = read_section(string_header, file);

  std::vector<std::string> symbol_table_strings;
  symbol_table_strings.reserve(symbol_count);

  for (int i = 0; i < symbol_count; i++) {
    symbol_table_strings.push_back(&string_table[symbol_table[i].st_name]);
  }

  return {std::move(symbol_table), std::move(symbol_table_strings)};
}

using elf_rel_table = std::vector<Elf32_Rel>;

elf_rel_table read_rel_table(const Elf32_Shdr &section_header,
                             std::fstream &file) {
  const auto symbol_count = section_header.sh_size / sizeof(Elf32_Rel);
  elf_bytes rel_table_bytes = read_section(section_header, file);
  const auto *begin =
      reinterpret_cast<const Elf32_Rel *>(rel_table_bytes.get());
  const auto *end = begin + symbol_count;

  return elf_rel_table(begin, end);
}

std::vector<Elf32_Phdr> read_program_headers(const Elf32_Ehdr &header,
                                             std::fstream &elf_file) {
  std::vector<Elf32_Phdr> program_headers(header.e_phnum);
  if (!elf_file.seekg(header.e_phoff))
    throw std::runtime_error("Couldn't read sections");

  for (int i = 0; i < header.e_phnum; i++) {
    if (!elf_file.read(reinterpret_cast<char *>(&program_headers[i]),
                       header.e_phentsize))
      throw std::runtime_error("Couldn't read elf section header");
  }

  return program_headers;
}

} // namespace elf_utils
