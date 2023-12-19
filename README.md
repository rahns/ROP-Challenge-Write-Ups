This repository is a collection of my work on various ROP challenges.

The ROPEmporium directory includes my write-ups for the `x86` challenges published here: [https://ropemporium.com/](https://ropemporium.com/). They start off very simple, then each challenge gets progressively harder.

The ASLR+DEP Bypass directory contains an exploit and write up that I wrote for a `x86_64` example vulnerable binary. The exploit is an example of the `ret2libc` technique. It leaks a pointer to LIBC then pops a shell using `system(/bin/sh)`.
