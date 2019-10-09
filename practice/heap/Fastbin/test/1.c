#include <malloc.h>
int main(){
    void * chunk1, *chunk2;
    chunk1 = malloc(10);
    chunk2 = malloc(10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
