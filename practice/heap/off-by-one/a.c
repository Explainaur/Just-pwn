#include<stdio.h>
struct book{
    int id;
    char *name;
    char *description;
    int size;
};
int main(){
    printf("%d\n",sizeof(int));
    printf("%d\n",sizeof(struct book));
    printf("%d\n",sizeof(char *));
    return 0;
}
