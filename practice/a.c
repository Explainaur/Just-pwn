#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *ptr = (char *)malloc(10);
    strcpy(ptr, "aaa");
    printf("%p\n", ptr);
    printf("%s\n", ptr);

    printf("---- Free ----\n");
    free(ptr);

    printf("%p\n", ptr);
    strcpy(ptr, "bbb");
    printf("%s", ptr);
    
    return 0;
}
