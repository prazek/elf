#include "trampolines.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <sys/mman.h>
#include <system_error>

namespace trampolines {
namespace {

/* My appologies for using terible AT&T asm syntax,
 * I was just copying it from objdump
 */
constexpr unsigned char X = 0;
constexpr int NUM_PASSING_REGISTERS = 6;
constexpr int MOVE_64_TO_REGISTER_OFFSET_BYTE = 4;
constexpr unsigned char MOVE_64_TO_REGISTER[NUM_PASSING_REGISTERS + 1][5] = {
  {0x49, 0x8b, 0x7c, 0x24, X}, //	movq	X(%r12), %rdi
  {0x49, 0x8b, 0x74, 0x24, X}, //	movq	X(%r12), %rsi
  {0x49, 0x8b, 0x54, 0x24, X}, //	movq	X(%r12), %rdx
  {0x49, 0x8b, 0x4c, 0x24, X}, //	movq	X(%r12), %rcx
  {0x4d, 0x8b, 0x44, 0x24, X}, //	movq	X(%r12), %r8
  {0x4d, 0x8b, 0x4c, 0x24, X}, // 	movq	X(%r12), %r9
  {0x49, 0x8b, 0x44, 0x24, X}  //	movq	X(%r12), %rax
};

int set_register_64(unsigned arg_num, int stack_offset, char *code) {
  if (arg_num < NUM_PASSING_REGISTERS) {
    assert(sizeof(MOVE_64_TO_REGISTER[0]) == 5);
    std::memcpy(code, MOVE_64_TO_REGISTER[arg_num], sizeof(MOVE_64_TO_REGISTER[0]));
  } else { // Put into rax
    std::memcpy(code,
           MOVE_64_TO_REGISTER[NUM_PASSING_REGISTERS],
           sizeof(MOVE_64_TO_REGISTER[0]));
  }
  assert(stack_offset < 127);
  auto offset = static_cast<char>(stack_offset);
  std::memcpy(code + MOVE_64_TO_REGISTER_OFFSET_BYTE, &offset, 1);
  return sizeof(MOVE_64_TO_REGISTER[0]);
}

constexpr int MOVE_32_TO_REGISTER_OFFSET_BYTE = 4;
constexpr unsigned char MOVE_32_TO_REGISTER[NUM_PASSING_REGISTERS + 1][5] = {
  {0x41, 0x8b, 0x7c, 0x24, X}, // 	movl	X(%r12), %edi
  {0x41, 0x8b, 0x74, 0x24, X}, // 	movl	X(%r12), %esi
  {0x41, 0x8b, 0x54, 0x24, X}, // 	movl	X(%r12), %edx
  {0x41, 0x8b, 0x4c, 0x24, X}, // 	movl	X(%r12), %ecx
  {0x45, 0x8b, 0x44, 0x24, X}, // 	movl	X(%r12), %r8d
  {0x45, 0x8b, 0x4c, 0x24, X}, // 	movl	X(%r12), %r9d
  {0x41, 0x8b, 0x44, 0x24, X}, // 	movl	X(%r12), %eax
};

int set_register_32(unsigned arg_num, int stack_offset, char *code) {
  if (arg_num < NUM_PASSING_REGISTERS) {
    assert(sizeof(MOVE_32_TO_REGISTER[0]) == 5);
    std::memcpy(code, MOVE_32_TO_REGISTER[arg_num], sizeof(MOVE_32_TO_REGISTER[0]));
  } else { // Put into rax
    std::memcpy(code,
           MOVE_32_TO_REGISTER[NUM_PASSING_REGISTERS],
           sizeof(MOVE_32_TO_REGISTER[0]));
  }
  assert(stack_offset < 127);
  auto offset = static_cast<char>(stack_offset);
  std::memcpy(code + MOVE_32_TO_REGISTER_OFFSET_BYTE, &offset, 1);
  return sizeof(MOVE_32_TO_REGISTER[0]);
}

constexpr int MOVE_32_SIGNED_TO_REGISTER_OFFSET_BYTE = 4;
constexpr unsigned char
  MOVE_32_SIGNED_TO_REGISTER[NUM_PASSING_REGISTERS + 1][5] = {
  {0x49, 0x63, 0x7c, 0x24, X}, //	movslq	X(%r12), %rdi
  {0x49, 0x63, 0x74, 0x24, X}, //	movslq	X(%r12), %rsi
  {0x49, 0x63, 0x54, 0x24, X}, //	movslq	X(%r12), %rdx
  {0x49, 0x63, 0x4c, 0x24, X}, //	movslq	X(%r12), %rcx
  {0x4d, 0x63, 0x44, 0x24, X}, //	movslq	X(%r12), %r8
  {0x4d, 0x63, 0x4c, 0x24, X}, //	movslq	X(%r12), %r9
  {0x49, 0x63, 0x44, 0x24, X}  //	movslq	X(%r12), %rax
};

int
set_register_signed_extend_32(unsigned arg_num, int stack_offset, char *code) {
  if (arg_num < NUM_PASSING_REGISTERS) {
    assert(sizeof(MOVE_32_SIGNED_TO_REGISTER[0]) == 5);
    std::memcpy(code,
           MOVE_32_SIGNED_TO_REGISTER[arg_num],
           sizeof(MOVE_32_SIGNED_TO_REGISTER[0]));
  } else { // Put into rax
    std::memcpy(code,
           MOVE_32_SIGNED_TO_REGISTER[NUM_PASSING_REGISTERS],
           sizeof(MOVE_32_SIGNED_TO_REGISTER[0]));
  }
  assert(stack_offset < 127);
  auto offset = static_cast<char>(stack_offset);
  std::memcpy(code + MOVE_32_SIGNED_TO_REGISTER_OFFSET_BYTE, &offset, 1);
  return sizeof(MOVE_32_TO_REGISTER[0]);
}

int set_register(unsigned arg_num, type arg_type, int stack_offset,
                 char *code) {
  switch (arg_type) {
    case type::TYPE_LONG_LONG:
    case type::TYPE_UNSIGNED_LONG_LONG:
      return set_register_64(arg_num, stack_offset, code);
    case type::TYPE_PTR:
    case type::TYPE_UNSIGNED_LONG:
    case type::TYPE_UNSIGNED_INT:
      return set_register_32(arg_num, stack_offset, code);
    case type::TYPE_LONG:
    case type::TYPE_INT:
      return set_register_signed_extend_32(arg_num, stack_offset, code);
    case type::TYPE_VOID:
      throw std::runtime_error("Arg can't be void");
  }
  assert(false && "unreachable");
}

int size_of_type_32(type arg_type) {
  switch (arg_type) {
    case type::TYPE_LONG_LONG:
    case type::TYPE_UNSIGNED_LONG_LONG:
      return 8;
    case type::TYPE_INT:
    case type::TYPE_UNSIGNED_INT:
    case type::TYPE_LONG:
    case type::TYPE_UNSIGNED_LONG:
    case type::TYPE_PTR:
      return 4;
    case type::TYPE_VOID:
      throw std::runtime_error("Arg can't be void");
  }
  assert(false && "Unreachable");
}


const unsigned char MOV_64_RAX_TO_STACK[] = {
  0x50  // pushq	%rax
};

int push_arg_to_stack(char *code) {
  std::memcpy(code, MOV_64_RAX_TO_STACK, sizeof(MOV_64_RAX_TO_STACK));
  return sizeof(MOV_64_RAX_TO_STACK);
}

int get_stack_offset_for_last_arg(const function &func) {
  int stack_offset = 0;
  for (int arg_num = 0; arg_num < func.nargs - 1; arg_num++) {
    stack_offset += size_of_type_32(func.args[arg_num]);
  }
  return stack_offset;
}


void set_registers(const function &func, char *&code) {
  static const int RETURN_PTR_SIZE = 4;
  int stack_offset = RETURN_PTR_SIZE;
  // Firstly put arguments to registers
  for (int arg_num = 0; arg_num < std::min(func.nargs, NUM_PASSING_REGISTERS);
       arg_num++) {
    code += set_register(arg_num, func.args[arg_num], stack_offset, code);
    stack_offset += size_of_type_32(func.args[arg_num]);
  }

  stack_offset = RETURN_PTR_SIZE + get_stack_offset_for_last_arg(func);
  // Rest of the arguments need to be put on the stack.
  for (int arg_num = func.nargs - 1; arg_num >= NUM_PASSING_REGISTERS;
       arg_num--) {
    code += set_register(arg_num, func.args[arg_num], stack_offset, code);
    stack_offset -= size_of_type_32(func.args[arg_num - 1]);
    code += push_arg_to_stack(code);
  }
}

static int exit_code = 0;
jmp_buf exit_buff;
__attribute__((noreturn)) void exit_64bit(int code) {
  exit_code = code;
  longjmp(exit_buff, 1);
}

// This code switches to 64 bit mode and continue executing next 64bits
// instructions.
const unsigned char TRAMPOLINE_SWITCH_TO_64_BITS[] = {
  0x6a, 0x33,           // 0: push   $0x33
  0x68, 00, 00, 00, 00, // 2: push   $0x0
  0xcb                  // 7: lret
};

// In 32 bit calling convention edi and esi registers do not change when calling
// function, which means we need to save them, as 64 bit code does not have this
// requirement.
const unsigned char SAVE_EDI_AND_ESI[] = {
  0x41, 0x89, 0xfe, //   mov    %edi,%r14d
  0x41, 0x89, 0xf7  //   mov    %esi,%r15d

};

// Before call, we need to fix aslignment of stack.
const unsigned char FIX_ALIGNMENT_OF_STACK[] = {
  0x49, 0x89, 0xe4,       // mov    %rsp,%r12
  0x48, 0x83, 0xe4, 0xf0, // and    $0xfffffffffffffff0,%rsp
};

const unsigned int FN_64_ADDR_OFFSET = 2;
const unsigned char CALL_FN[] = {
  0x48, 0xb8, 00, 00, 00, 00, 00, 00, 00, 00,    // movabs <PUT_ADDR_HERE>,%rax
  0xff, 0xd0                                     // callq  *%rax
};

const unsigned char CHECK_RETURNED_SIGNED_LONG[] = {
  0xba, 0x00, 0x00, 0x00, 0x80, //  mov    $0x80000000,%edx
  0xb9, 0xff, 0xff, 0xff, 0xff, //  mov    $0xffffffff,%ecx
  0x48, 0x01, 0xc2,             //  add    %rax,%rdx
  0x48, 0x39, 0xca,             //  cmp    %rcx,%rdx
  0x76, 0x1a,                   //  jbe    b3 <ok>
  0x83, 0xcf, 0xff,             //  or     $0xffffffff,%edi
  // Here put call to exit
};

const unsigned char CHECK_RETURNED_UNSIGNED_LONG_OR_PTR[] = {
  0xb9, 0xff, 0xff, 0xff, 0xff, // mov    $0xffffffff,%ecx
  0x48, 0x39, 0xc8,             // cmp    %rcx,%rax
  0x76, 0x08,                   // jbe    b3 <ok>
  0x83, 0xcf, 0xff,             // or     $0xffffffff,%edi
  // HERE put be a call to exit.
};

const unsigned char MOVE_UPPER_BITS_TO_EDX[] = {
  0x48, 0x89, 0xc2,      // mov    %rax,%rdx
  0x48, 0xc1, 0xea, 0x20 // shr    $0x20,%rdx
};

const unsigned char REMOVE_ALIGNMENT_OF_STACK[] = {
  0x4c, 0x89, 0xe4 // mov    %r12,%rsp
};

const unsigned char RESTORE_EDI_AND_ESI[] = {
  0x44, 0x89, 0xf7, // mov    %r14d,%edi
  0x44, 0x89, 0xfe  // mov    %r15d,%esi
};


const int RETURN_TO_32_BITS_ADDR_INDX = 15;
const unsigned char RETURN_TO_32_BITS[] = {
  0x48, 0x83, 0xec, 0x08,                         // sub    $0x8,%rsp
  0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // movl   $0x23,0x4(%rsp)
  0xc7, 0x04, 0x24, 00, 00, 00,
  00,               // movl   <PUT_ADDR_HERE>,(%rsp)
  0xcb                                            // lret
};

const unsigned char SET_32_BITS_SEGMENTS[] = {
  0x6a, 0x2b, // push   $0x2b
  0x1f,       // pop    %ds
  0x6a, 0x2b, // push   $0x2b
  0x07        // pop    %es
};

const unsigned char RETURN_FROM_TRAMPOLINE[] = {
  0xc3, // ret
};

void set_returned_value(type return_type, char *&code) {
  // If returned value is 64 bit signed long, we need to check if it fits
  // 32 bit long.
  if (return_type == TYPE_LONG) {
    std::memcpy(code, CHECK_RETURNED_SIGNED_LONG,
                sizeof(CHECK_RETURNED_SIGNED_LONG));
    code += sizeof(CHECK_RETURNED_SIGNED_LONG);
    std::memcpy(code, CALL_FN, sizeof(CALL_FN));
    void *exit_addr = (void *) exit_64bit;
    std::memcpy(code + FN_64_ADDR_OFFSET, &exit_addr, 8);
    code += sizeof(CALL_FN);
    return;
  }
  // Similarly, if value is 64 bit ptr or 64 bit unsigned long we need to check
  // if it fits 32 bits.
  if (return_type == TYPE_UNSIGNED_LONG || return_type == TYPE_PTR) {
    std::memcpy(code, CHECK_RETURNED_UNSIGNED_LONG_OR_PTR,
                sizeof(CHECK_RETURNED_UNSIGNED_LONG_OR_PTR));
    code += sizeof(CHECK_RETURNED_UNSIGNED_LONG_OR_PTR);
    std::memcpy(code, CALL_FN, sizeof(CALL_FN));
    void *exit_addr = (void *) exit_64bit;
    std::memcpy(code + FN_64_ADDR_OFFSET, &exit_addr, 8);
    code += sizeof(CALL_FN);
    return;
  }
  // move 64 bit return value from rax to edx:eax
  if (return_type == TYPE_UNSIGNED_LONG_LONG || return_type == TYPE_LONG_LONG) {
    std::memcpy(code, MOVE_UPPER_BITS_TO_EDX, sizeof(MOVE_UPPER_BITS_TO_EDX));
    code += sizeof(MOVE_UPPER_BITS_TO_EDX);
    return;
  }
}

} // namespace

jmp_buf& get_exit_jump_buffer() {
  return exit_buff;
}

int get_exit_code() {
  return exit_code;
}

constexpr int MAX_TRAMPOLINE_SIZE = 250;

void *create_trampoline(const function &func, char *&code, char *code_end) {
  char *begin_of_function = code;
  assert(code_end - code > MAX_TRAMPOLINE_SIZE
  && "Need to have enough space for trampoline");

  std::memcpy(code, TRAMPOLINE_SWITCH_TO_64_BITS,
              sizeof(TRAMPOLINE_SWITCH_TO_64_BITS));
  char *addr_aftertrampoline = code + sizeof(TRAMPOLINE_SWITCH_TO_64_BITS);
  std::memcpy(code + 3, &addr_aftertrampoline, 4);
  code += sizeof(TRAMPOLINE_SWITCH_TO_64_BITS);

  std::memcpy(code, SAVE_EDI_AND_ESI, sizeof(SAVE_EDI_AND_ESI));
  code += sizeof(SAVE_EDI_AND_ESI);

  std::memcpy(code, FIX_ALIGNMENT_OF_STACK, sizeof(FIX_ALIGNMENT_OF_STACK));
  code += sizeof(FIX_ALIGNMENT_OF_STACK);

  set_registers(func, code);

  std::memcpy(code, CALL_FN, sizeof(CALL_FN));
  // Put address of real function
  std::memcpy(code + 2, &func.code, 8);
  code += sizeof(CALL_FN);

  std::memcpy(code, REMOVE_ALIGNMENT_OF_STACK, sizeof(REMOVE_ALIGNMENT_OF_STACK));
  code += sizeof(REMOVE_ALIGNMENT_OF_STACK);

  set_returned_value(func.result, code);

  std::memcpy(code, RESTORE_EDI_AND_ESI, sizeof(RESTORE_EDI_AND_ESI));
  code += sizeof(RESTORE_EDI_AND_ESI);

  std::memcpy(code, RETURN_TO_32_BITS, sizeof(RETURN_TO_32_BITS));
  char *addr_after_returning_to_32_bit = code + sizeof(RETURN_TO_32_BITS);
  std::memcpy(code + RETURN_TO_32_BITS_ADDR_INDX, &addr_after_returning_to_32_bit,
              4);
  code += sizeof(RETURN_TO_32_BITS);

  std::memcpy(code, SET_32_BITS_SEGMENTS, sizeof(SET_32_BITS_SEGMENTS));
  code += sizeof(SET_32_BITS_SEGMENTS);

  std::memcpy(code, RETURN_FROM_TRAMPOLINE, sizeof(RETURN_FROM_TRAMPOLINE));
  code += sizeof(RETURN_FROM_TRAMPOLINE);

  return begin_of_function;
}

std::unordered_map<std::string, void *>
create_trampolines(const function *funcs, const int nfuncs,
                   std::vector<mmap_utils::mapped_mem> &alloced_trampolines) {


  constexpr int TRAMPOLINES_BUFFER_SIZE = 1024 * 4;
  auto alloc_trampolines_code = [] {
    char *memory = (char *) mmap(NULL, TRAMPOLINES_BUFFER_SIZE,
                                 PROT_EXEC | PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (memory == MAP_FAILED)
      throw std::system_error(errno, std::system_category(), "Can't allocate memory for trampolines");
    return mmap_utils::mapped_mem(memory, mmap_utils::Unmapper{TRAMPOLINES_BUFFER_SIZE});
  };


  char *trampolines_begin, *trampolines_end;
  auto increase_buffer = [&] {
    alloced_trampolines.push_back(alloc_trampolines_code());
    trampolines_begin = alloced_trampolines.back().get();
    trampolines_end = alloced_trampolines.back().get() + TRAMPOLINES_BUFFER_SIZE;
  };

  increase_buffer();
  std::unordered_map<std::string, void *> trampolines;

  auto check_and_alloc = [&] {
    if (trampolines_end - trampolines_begin < MAX_TRAMPOLINE_SIZE)
      increase_buffer();
  };

  for (int i = 0; i < nfuncs; i++) {
    check_and_alloc();
    trampolines[funcs[i].name] = create_trampoline(funcs[i], trampolines_begin, trampolines_end);
  }

  // Additionaly, we add trampoline for the exit function.
  enum type exit_types[] = {TYPE_INT};
  struct function exit_func = {"exit", exit_types, 1, TYPE_VOID,
                               (void *) exit_64bit};

  check_and_alloc();
  trampolines["exit"] = create_trampoline(exit_func, trampolines_begin, trampolines_end);

  for (auto &trampoline_buff : alloced_trampolines) {
    if (mprotect(trampoline_buff.get(),
                 TRAMPOLINES_BUFFER_SIZE,
                 PROT_EXEC | PROT_READ) != 0)
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to protect mapped region");

  }

  return trampolines;
}

} // namespace trampolines