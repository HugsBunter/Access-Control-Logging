#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "acmonitor.h"

#define MAX_USERS 4
#define MAX_FILES 100
#define MAX_ACESSES 1000
#define MAX_CHAR_FILE_NAME 50

typedef struct {
  int uid;
  char *filename[MAX_FILES];
  int attempts;
}MaliciousUser;

typedef struct {
  char *path;
  char *fingerprints[MAX_ACESSES];
  int uids[MAX_USERS];
  int modTimes;
}FileMod;

int findMal(unsigned char* path){

    FILE* myFile = fopen(path, "r");
    if (myFile == NULL) {
        perror("Error opening file");
        return -1;
     }
    
    MaliciousUser maliciousUsers[MAX_USERS];
    //initialize the users
    for(int i = 0; i < MAX_USERS; i++){
        maliciousUsers[i].uid = 0;
        maliciousUsers[i].attempts = 0;

       for(int j = 0; j< MAX_FILES; j++){
          maliciousUsers[i].filename[j] = malloc(MAX_CHAR_FILE_NAME * sizeof(char));

          // Check if memory allocation is successful
          if (maliciousUsers[i].filename[j] == NULL) {
              perror("Memory allocation failed");
              return -1;
          }
          strcpy(maliciousUsers[i].filename[j], " ");
       }
      }

    char line[50];
    int line_count = 0;
    int uid;
    char *motinor_path;
    int flag = 0;
    int user_found = 0;
    motinor_path = malloc(256);
    
    // Process each line
    while (fgets(line, sizeof(line), myFile) != NULL) {
        
        if(line_count == 0) {
          if(sscanf(line, "The UID id: %d", &uid) == 0)
            printf("Error occured in line count %d.\n", line_count); 
        }else if(line_count == 1){
          if(sscanf(line, "The file name is: %s", motinor_path) == 0)
            printf("Error occured in line count %d.\n", line_count); 
        }else if(line_count == 5){
          if(sscanf(line, "Is-action-denied: %d", &flag) == 0)
            printf("Error occured in line count %d.\n", line_count);             
        }else if (line_count == 7) {
          // Process the complete log entry
          if(flag == 1){                                //action_denied == 1
            for (int i = 0; i < MAX_USERS; i++) {
              if (maliciousUsers[i].uid == uid){
                for(int j = 0; j < MAX_FILES; j++){
                  if(strcmp(maliciousUsers[i].filename[j],motinor_path) == 0){
                    break;
                  }else if(strcmp(maliciousUsers[i].filename[j]," ") == 0){ //if there is not an other attempt for this file
                    strcpy(maliciousUsers[i].filename[j],motinor_path);
                    maliciousUsers[i].attempts++;
                    break;
                  }   
                }   
              }else if(maliciousUsers[i].uid == 0){
                for(int k=0; k<MAX_USERS; k++){
                  if(maliciousUsers[k].uid == uid){
                    user_found = 1;
                    break;
                  }    
                }
                if(user_found == 1){
                  user_found = 0;
                  break;
                }
                maliciousUsers[i].uid = uid;
                strcpy(maliciousUsers[i].filename[0],motinor_path);
                maliciousUsers[i].attempts++;
                break;
              }     
            }
          }
          line_count = -1;
        }

        line_count++;  
    }

    FILE * maliciousFile = fopen("mal_users_monitor.txt", "w");
    fprintf(maliciousFile,"\nMALICIOUS USERS:");

    for(int i = 0; i < MAX_USERS; i++){
        if(maliciousUsers[i].attempts > 6){
            if (maliciousFile == NULL) {
                perror("Error opening file");
                return 1;
            }
            fprintf(maliciousFile,"\n%d\n",maliciousUsers[i].uid);   
        }
    }
    
    for(int i = 0; i < MAX_USERS; i++){
       for(int j = 0; j< MAX_FILES; j++){
        free(maliciousUsers[i].filename[j]);
       }
    }
    free(motinor_path);
    fclose(myFile);

  return 1;
}

int file_modifications(unsigned char* path){

  FILE* myFile = fopen("file_logging.log", "r");
  if (myFile == NULL) {
    perror("Error opening file");
    return -1;
  }

  FileMod file_mod;

  //initialization
  file_mod.modTimes = 0;
  file_mod.path = malloc(MAX_CHAR_FILE_NAME * sizeof(char));
  strcpy(file_mod.path,path);
  for(int i = 0; i < MAX_USERS;i++){
    file_mod.uids[i] = 0;
  }
  for(int j = 0; j< MAX_ACESSES; j++){
    file_mod.fingerprints[j] = malloc(32);// dessssssssss 16
      if (file_mod.fingerprints[j]  == NULL) {
        perror("Memory allocation failed");
        return -1;
      }
    strcpy(file_mod.fingerprints[j], " ");
  }

  char line[50];
  int line_count = 0;
  int uid;
  int access_type_flag = 0;
  int access_denied_flag = 0;
  char *motinor_path;
  char *hash_fingerprint;
  int user_found = 0;
  motinor_path = malloc(256);
  hash_fingerprint = malloc(32);//des gia 16


  while (fgets(line, sizeof(line), myFile) != NULL){
    if(line_count == 0) {
        if(sscanf(line, "The UID id: %d", &uid) == 0)
          printf("Error occured in line count %d.\n", line_count); 
      }else if(line_count == 1){
        if(sscanf(line, "The file name is: %s", motinor_path) == 0)
          printf("Error occured in line count %d.\n", line_count); 
      }else if(line_count == 4){
        if(sscanf(line, "The access type: %d", &access_type_flag) == 0)
          printf("Error occured in line count %d.\n", line_count);
      }else if(line_count == 5){
          if(sscanf(line, "Is-action-denied: %d", &access_denied_flag) == 0)
            printf("Error occured in line count %d.\n", line_count);
      }else if(line_count == 6){
        if(sscanf(line, "Fingerprint: %s", hash_fingerprint) == 0)
          printf("Error occured in line count %d.\n", line_count); 
      }else if (line_count == 7){
        int flag = 0;
        // end of log entry //
        if(strcmp(file_mod.path,motinor_path) == 0){

          //for-loop for file modification
          for(int i = 0; i < MAX_ACESSES; i++){ // search all the hash fingerprints and check if the previous one is the same with the current
            if(strcmp(file_mod.fingerprints[0]," ") == 0){
              strcpy(file_mod.fingerprints[0], hash_fingerprint);
              break;
            }else if(strcmp(file_mod.fingerprints[i-1],hash_fingerprint) == 0 && strcmp(file_mod.fingerprints[0]," ") == 0){
              break;
            }else if(strcmp(file_mod.fingerprints[i-1],hash_fingerprint) != 0 && strcmp(file_mod.fingerprints[0]," ") == 0){
              strcpy(file_mod.fingerprints[i], hash_fingerprint);
              file_mod.modTimes++;
              break;
            }
          }

          if(access_denied_flag == 0 && access_type_flag != 0){
            //for-loop for users that accessed 
            for(int i = 0; i < MAX_USERS; i++){  
              if(file_mod.uids[i] == uid){ 
                flag = 1; //user exists
                break;
              }
              if(file_mod.uids[i] == 0 && flag == 0){
                file_mod.uids[i] = uid;
                break;
              }
            }
          }
        }
        line_count = -1;
      }
    line_count++;  
  }  

  FILE * fileMon = fopen("file_monitor.txt", "w");

  fprintf(fileMon,"For the file: %s\n"
                  "\tthe number of modifications are:%d\n"
                  "\tThe uids of the users accessed the file are: ",file_mod.path,file_mod.modTimes);  
  
  for(int i = 0; i < MAX_USERS; i++){
    if (fileMon == NULL) {
        perror("Error opening file");
        return 1;
    }
    if(file_mod.uids[i] == 0){
      break;
    }
    fprintf(fileMon,"%d",file_mod.uids[i]);
    if(i < MAX_USERS-1 && file_mod.uids[i+1] != 0){
      fprintf(fileMon,", ");
    }
  }


  fclose(fileMon);
  fclose(myFile);
  free(file_mod.path);
  free(motinor_path);
  free(hash_fingerprint);
  for(int j = 0; j< MAX_ACESSES; j++){
    free(file_mod.fingerprints[j]);
  }
  
  return 0;
}