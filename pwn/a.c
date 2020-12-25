#include <sys/syscall.h>
#include <string.h>

void sys_put(char* c, int len) {
    // write(int fd, const void *buf, size_t count); 
    __asm__ __volatile__(
        "int3 \n\t"
        "push %%rdi \n\t"
        "push %%rsi \n\t"
        "mov $1, %%rax\n\t"   
        "mov $1, %%rdi \n\t"    
        "pop %%rdx \n\t"
        "pop %%rsi \n\t"
        "syscall \n\t"
        "leave \n\t"
        "ret \n\t"
        :::);                   // clobbers
}

int sys_exec(char *sh, char* argv[], char *envp[]) {
    __asm__ __volatile__(
        "int3 \n\t"
        "push %%rdi \n\t"
        "push %%rsi \n\t"
        "push %%rdx \n\t"
        "mov $59, %%rax \n\t"
        "syscall \n\t"
        "leave \n\t"
        "ret \n\t"
        :::);
}

int put_string(char *str) {
    int len = strlen(str);
    sys_put(str, len);
}

int exec(char *cmd) {
    char *args[4] = {"/bin/sh", "-c", cmd, NULL};
    sys_exec(args[0], args, NULL);
}

int main() {
    exec("ls");
}
