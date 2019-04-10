for exe in cleanup exit long-ptr memsz missing-sym mprotect mprotect2 multiargs multicall stacksize; do
   echo $exe
   ./"$exe"-64
done
