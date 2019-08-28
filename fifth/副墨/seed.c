#include<stdlib.h>
#include<time.h>

int main(){
    int seed[2];
    * seed = time(0);
    srand(0x0101010101010101);
    //srand(time(0));
    int i = 0;
    for(i=0;i<10;i++){
        printf("%d\n",rand()%0x1869F+1);
    }
    return 0;
}
