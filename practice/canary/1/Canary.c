#include <stdio.h>
#include <string.h>

void vul(char *msg_orig)
{
    char msg[128];
    memcpy(msg,msg_orig,128);
    printf(msg);

    char shellcode[64];
    puts("Now ,plz give me your shellcode:");
    read(0,shellcode,256);

}


int main()
{
    puts("So plz leave your message:");
    char msg[128];
    memset(msg,0,128);
    read(0,msg,128);
    vul(msg);
    puts("Bye!");
    return 0;
}
