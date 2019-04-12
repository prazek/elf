#pragma once

#include <sys/mman.h>
#include <memory>

namespace mmap_utils {

struct Unmapper {
  uint32_t prog_size;

  void operator()(char* ptr) const { munmap(ptr, prog_size); }
};

using mapped_mem = std::unique_ptr<char[], Unmapper>;
}