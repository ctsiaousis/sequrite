# Buffer Overflow
The vulnerable program of this assignment is Greeter. It simply asks for your name and kindly greets you. Initially, it asks the name of the user and call sthe​ `readString` function, readString uses `​gets` ​function inorder to place the name of the user in a local buffer (placed in the stack).Then,the local buffer is copied in a global buffer and the readString function returns. Finally, the program calls `​printf` ​function​ with the global buffer as an argument in order to print “Hello<user>, have a nice day.”.

In the script `greedier.py` is demonstrated a simple buffer overflow for Arbitrary code execution.

### Helpful gdb commands

`disassemble readString` to find the return address of the function and set a breakpoint

`break *0x080...` to set a breakpoint on specific address

To do stuff each time a function returns you can define a hook like this:
```
define hook-stop
    x/1i $eip
    x/8wx $esp
    end
```
First line prints the next command from the instruction pointer.
Second line e`x`amines `8` `w`ords as he`x` from the stack pointer

`info registers` To print info about the registers

`x/50wx Name` e`x`amines `50` `w`ords as he`x` from the variable Name

`p &Name` prints the address of the variable Name

`x/1000s $esp` examine 1000 words from stack as strings. Cool to see env variables.

# TLDR;
To test it run
```
(python3 greedier.py; cat) | ./Greeter 
```