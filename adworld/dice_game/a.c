#include<stdio.h>
#include<stdlib.h>
#include<time.h>
int main(int argc, const char *argv[])
{
    int seed[2];
    *seed = time(0);
    srand(0);
    int i=0;
    for(i=0;i<50;i++){
        printf("%d\n",rand()%6+1);
    }
    return 0;
}
