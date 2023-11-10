#include <stdio.h>

int main(){
    printf("Calling the fopen() function... \n");

    FILE *fd = fopen("test_read_1.txt", "r");
    if(!fd) {
        printf("fopen() return NULL\n");
        return 1;
    }
    printf("fopen() succeedded\n\n\n");

    FILE *fd1 = fopen("test_read_2.txt", "r");
    if(!fd1) {
        printf("fopen() return NULL\n");
        return 1;
    }

    FILE *fd2 = fopen("test_write_3.txt", "w");
    if(!fd2) {
        printf("fopen() return NULL\n");
        return 1;
    }


    char str[] = "What is the password?";
    fwrite(str, 1, sizeof(str) - 1, fd2);
    fclose(fd2);
    printf("fwrite() succeedded\n");

}