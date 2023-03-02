# The idea at glance

The process starts with a binary function image, which is disassembled 
using the libcapstone library. A control flow graph (cfg) is then generated 
for the function. The resulting cfg image contains, among the others,
two bubbles - a green one representing an instruction block containing a 
`syscall`, and a red one representing an instruction block containing a 
`ret` instruction.

The next step involves finding a path from the entry point to the `syscall`
containing instructions block. Once the path is identified, a guided 
execution is performed using the libunicorn library to execute each 
block in the path one by one. During the execution of the `syscall`
containing instructions block, the register values are read to determine 
the syscall number.

Overall, this process involves analyzing a binary function to identify 
a syscall instruction block and determine its syscall number through 
guided execution.

![image info](./imgs/sys_no.png)
