#include <stdio.h>
#include "acmonitor.h"

int main(){
    printf("Calling the fopen() function... \n");

    FILE *fd = fopen("test_read_1.txt", "w");
    if(!fd) {
        printf("fopen() return NULL\n");
        //return 1;
    }
    printf("fopen() succeedded\n\n\n");

    FILE *fd1 = fopen("test_read_2.txt", "w");
    if(!fd1) {
        printf("fopen() return NULL\n");
        //return 1;
    }

    FILE *fd2 = fopen("test_write_3.txt", "w");
    if(!fd2) {
        printf("fopen() return NULL\n");
        //return 1;
    }

/////////////////////////////////////////////////////////////////
    FILE *fd3 = fopen("test_read_4.txt", "w");
    if(!fd3) {
        printf("fopen() return NULL\n");
        //return 1;
    }
    printf("fopen() succeedded\n\n\n");

    FILE *fd4 = fopen("test_read_5.txt", "w");
    if(!fd4) {
        printf("fopen() return NULL\n");
        //return 1;
    }
    printf("fopen() succeedded\n\n\n");

    FILE *fd5 = fopen("test_read_6.txt", "w");
    if(!fd5) {
        printf("fopen() return NULL\n");
        //return 1;
    }
    printf("fopen() succeedded\n\n\n");

    FILE *fd6 = fopen("test_read_7.txt", "w");
    if(!fd6) {
        printf("fopen() return NULL\n");
        //return 1;
    }
    printf("fopen() succeedded\n\n\n");
    
    


    //////
    // char str[] = "What is the password?";
    // fwrite(str, 1, sizeof(str) - 1, fd2);
    // fclose(fd2);
    // printf("fwrite() succeedded\n");

    
    findMal("file_logging.log");

    file_modifications("test_read_2.txt");
}