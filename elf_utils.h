#pragma once

#include <elf.h>
#include <fstream>
#include <memory>
#include <vector>

namespace elf_utils {

std::vector<Elf32_Shdr> read_section_headers(const Elf32_Ehdr &header,
                                             std::fstream &file);

using elf_bytes = std::unique_ptr<const char[]>;

elf_bytes read_section(const Elf32_Shdr &section_header, std::fstream &file);

using elf_symbol_table = std::vector<Elf32_Sym>;
using elf_symbol_strings = std::vector<std::string>;

std::tuple<elf_symbol_table, elf_symbol_strings>
read_symbol_table(const Elf32_Shdr &section_header,
                  const Elf32_Shdr &string_header, std::fstream &file);

using elf_rel_table = std::vector<Elf32_Rel>;

elf_rel_table read_rel_table(const Elf32_Shdr &section_header,
                             std::fstream &file);

std::vector<Elf32_Phdr> read_program_headers(const Elf32_Ehdr &header,
                                             std::fstream &elf_file);

} // namespace elf_utils
