crossld_start is a function that while executing x86_64 code, start Elf32 executable [fname] with provided functions.
 For each function it creates a trampoline that:
 1. from 32 bit mode switches to 64 bit mode
 2. moves arguments to right registers for the x64 calling convention
 3. executes given function
 4. checks if returned value fits into return type, if not finished execution
    with code -1
 5. switches to 32 bit mode
 6. returns to 32 bit exec
  
 It then set all the relocations of the given executable. 
 For now, only REL is supported.
  
 In the end, it returns the code for the execution.
 
In elf_utils.h you can find usefull C++ functions for reading ELF32 file.

This is a one of the tasks of the Advanced Operating Systems course (Zawansowane Systemy Operacyjne) on MIMUW 
(University of Warsaw).
