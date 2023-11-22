#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

int main(int argc, char *argv[]){
    FILE *fd1, *fd2, *fd3, *fd4, *fd5, *fd6, *fd7;

    srand(time(NULL));

    int randomNum = rand();

    if(argc != 2) {
    printf("wrong input");
    return -1;
    }

    if(strcmp(argv[1],"-m") == 0){
        printf("\n\nCreate the files for testing...\n\n");
        fd1 = fopen("test_1.txt", "w");
        if(!fd1) {
            printf("fopen() return NULL\n");;
        }

        fd2 = fopen("test_2.txt", "w");
        if(!fd2) {
            printf("fopen() return NULL\n");
        }
        char str2[] = "Test test test test..";
        fwrite(str2, 1, sizeof(str2) - 1, fd2);
        
        fd3 = fopen("test_3.txt", "w");
        if(!fd3) {
            printf("fopen() return NULL\n");
        }
        char str3[] = "Test test test...";
        fwrite(str3, 1, sizeof(str3) - 1, fd3);


        fd4 = fopen("test_4.txt", "w");
        if(!fd4) {
            printf("fopen() return NULL\n");
        }
        char str4[] = "testing again...";
        fwrite(str4, 1, sizeof(str4) - 1, fd4);

        fd5 = fopen("test_5.txt", "w");
        if(!fd5) {
            printf("fopen() return NULL\n");
        } 
        char str5[] = "Test test test test...";
        fwrite(str5, 1, sizeof(str5) - 1, fd5);

        fd6 = fopen("test_6.txt", "w");
        if(!fd6) {
            printf("fopen() return NULL\n");
        }

        fd7 = fopen("test_7.txt", "w");
        if(!fd7) {
            printf("fopen() return NULL\n");
        }

        fclose(fd1);
        fclose(fd2);
        fclose(fd3);
        fclose(fd4);
        fclose(fd5);
        fclose(fd6);
        fclose(fd7);

    }else if(strcmp(argv[1],"-l") == 0){
        printf("\n\nLOCK FILES\n\n");
        
        //Read permission for the file's group.
        if(chmod("test_1.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_2.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_3.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_4.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_5.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_6.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_7.txt" ,0 ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        //try to access the locked files
        fd1 = fopen("test_1.txt", "w");
        if(!fd1) {
            printf("fopen() return NULL\n\n");;
        }

        fd2 = fopen("test_2.txt", "w");
        if(!fd2) {
            printf("fopen() return NULL\n\n");
        }
        
        fd3 = fopen("test_3.txt", "w");
        if(!fd3) {
            printf("fopen() return NULL\n\n");
        }

        fd4 = fopen("test_4.txt", "w");
        if(!fd4) {
            printf("fopen() return NULL\n\n");
        }

        fd5 = fopen("test_5.txt", "w");
        if(!fd5) {
            printf("fopen() return NULL\n\n");
        }

        fd6 = fopen("test_6.txt", "w");
        if(!fd6) {
            printf("fopen() return NULL\n\n");
        }

        fd7 = fopen("test_7.txt", "w");
        if(!fd7) {
            printf("fopen() return NULL\n\n");
        }

    }else if(strcmp(argv[1],"-u") == 0){
        //unlock all the locked files
        printf("\n\nUNLOCK FILES\n\n");
                    
        //Read, write, and search or execute permission for the file's group.
        if(chmod("test_1.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return 0;
        }

        if(chmod("test_2.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return 0;
        }

        if(chmod("test_3.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return 0;
        }

        if(chmod("test_4.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_5.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_6.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        if(chmod("test_7.txt" , S_IRGRP | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH ) < 0){ 
            printf("Error with chmod");
            return -1;
        }

        //access the unlocked files
        fd1 = fopen("test_1.txt", "w");
        if(!fd1) {
            printf("fopen() return NULL111\n\n");;
        }
        char str1[] = "Test";
        fwrite(str1, 1, sizeof(str1) - 1, fd1);

        fd2 = fopen("test_2.txt", "w");
        if(!fd2) {
            printf("fopen() return NULL\n\n");
        }
        char str2[] = "Hi I dont know what to write ;)";
        fwrite(str2, 1, sizeof(str2) - 1, fd2);
        
        fd3 = fopen("test_3.txt", "r");
        if(!fd3) {
            printf("fopen() return NULL\n\n");
        }
        char str3[] = "Test fwrite after unlocking";
        fwrite(str3, 1, sizeof(str3) - 1, fd3);

        fd4 = fopen("test_4.txt", "w");
        if(!fd4) {
            printf("fopen() return NULL\n");
        }
        fprintf(fd4,"Here we write random numbers: %d",randomNum);

        fd5 = fopen("test_5.txt", "r");
        if(!fd5) {
            printf("fopen() return NULL\n\n");
        }

        fd6 = fopen("test_6.txt", "w");
        if(!fd6) {
            printf("fopen() return NULL\n\n");
        }
        fprintf(fd6,"Modificationssss");

        fd7 = fopen("test_7.txt", "w");
        if(!fd7) {
            printf("fopen() return NULL\n\n");
        }

        fclose(fd1);
        fclose(fd2);
        fclose(fd3);
        fclose(fd4);
        fclose(fd5);
        fclose(fd6);
        fclose(fd7);

    }else{
        printf("Wrong input!\n");
    }

    
    return 0;
}