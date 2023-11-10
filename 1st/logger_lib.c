#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <libgen.h>

int (*original_fprintf)(FILE *stream, const char *format, ...);

void md5_hash(const unsigned char *message, size_t message_len, unsigned char *hash)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("md5");
    unsigned int hash_len = 16;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, message_len);

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    EVP_MD_CTX_free(mdctx);
}

void logging(FILE *logFile, const char *path, int accessType, int access_denied, unsigned char *hash_fingerprint)
{
    original_fprintf = dlsym(RTLD_NEXT, "fprintf");

    uid_t uid = getuid();
    time_t t;
    struct tm *tm_info;
    time(&t);
    tm_info = localtime(&t);

    int day = tm_info->tm_mday;
    int month = tm_info->tm_mon + 1;
    int year = tm_info->tm_year + 1900;
    int hour = tm_info->tm_hour;
    int minute = tm_info->tm_min;
    int second = tm_info->tm_sec;

    (*original_fprintf)(logFile, "The UID id: %d\n"
                                "The file name is: %s\n"
                                "The date is: %02d/%02d/%04d\n"
                                "The timestamp: %02d:%02d:%02d\n"
                                "The access type: %d\n"
                                "Is-action-denied: %d\n",
                                uid, path, day, month, year, hour, minute, second, accessType, access_denied);

    if (hash_fingerprint != NULL)
    {
        (*original_fprintf)(logFile, "Fingerprint: ");
        for (int i = 0; i < 16; i++)
        {
            (*original_fprintf)(logFile, "%02x", hash_fingerprint[i]);
        }
        (*original_fprintf)(logFile, "\n\n");
    }
    else
    {
        (*original_fprintf)(logFile, "Fingerprint: NULL\n\n");
    }
}

FILE *fopen(const char *path, const char *mode)
{
    original_fprintf = dlsym(RTLD_NEXT, "fprintf");

    FILE *(*original_fopen)(const char *, const char *);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    int accessType = 0;
    int access_denied = 0;

    if (access(path, F_OK) != 0)
    {
        accessType = 0;
        printf("The file does not exist.\n");
    }
    else
    {
        accessType = 1;
        printf("The file exists.\n");
    }

    if (access(path, W_OK) == 0)
    {
        accessType = 2;
        printf("The file is writable.\n");
    }

    unsigned char *hash_fingerprint = NULL;
    hash_fingerprint = malloc(16);

    if (access(path, R_OK) != 0 && access(path, W_OK) != 0 && access(path, X_OK) != 0 && accessType == 1)
    {
        access_denied = 1;
        FILE *logFile = (*original_fopen)("file_logging.log", "a");

        logging(logFile, path, accessType, access_denied, NULL);

        printf("\nAccess denied.\n");
        return NULL;
    }
    else
    {
        access_denied = 0;
        printf("Access permitted.\n");
    }

    if (accessType == 0)
    {
        hash_fingerprint = NULL;
    }
    else
    {

        FILE *file_content = (*original_fopen)(path, "r");

        if (file_content == NULL)
        {
            (*original_fprintf)(stderr, "Error opening file for reading.\n");
            return NULL;
        }

        fseek(file_content, 0, SEEK_END); 
        long fileSize = ftell(file_content);
        fseek(file_content, 0, SEEK_SET); 
       
        unsigned char *cont_buffer = malloc(fileSize);
        if (cont_buffer == NULL)
        {
            (*original_fprintf)(stderr, "Error allocating memory for file content.\n");
            fclose(file_content);
            return NULL;
        }

        if (fread(cont_buffer, 1, fileSize, file_content) != fileSize)
        {
            (*original_fprintf)(stderr, "Error reading file content.\n");
            free(cont_buffer);
            fclose(file_content);
            return NULL;
        }

        fclose(file_content);

        // Calculate the MD5 hash on the binary content
        if(fileSize == 0)
            hash_fingerprint = NULL;
        else 
            md5_hash(cont_buffer, fileSize, hash_fingerprint);

        free(cont_buffer);
    }

    FILE *logFile = (*original_fopen)("file_logging.log", "a");

    logging(logFile, path, accessType, access_denied, hash_fingerprint);

    free(hash_fingerprint);
    fclose(logFile);
    return (*original_fopen)(path, mode);
}

const char* get_file_name(int fd) {
    static char path[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(path, path, sizeof(path) - 1);

    if (len != -1) {
        path[len] = '\0';
        return basename(path);
    }

    return NULL;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{

    size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");

    FILE *(*original_fopen)(const char *, const char *);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    int fd = fileno(stream);
    const char* path = get_file_name(fd);
    
    int accessType = 0;

    if (access(path, W_OK) == 0)
   {
        accessType = 2;
        printf("The file is writable.\n"); 

        unsigned char *hash_fingerprint = NULL;
        hash_fingerprint = malloc(16);
        // Calculate the MD5 hash on the binary content
        md5_hash(ptr, nmemb, hash_fingerprint);

        FILE *logFile = (*original_fopen)("file_logging.log", "a");

        logging(logFile, path, accessType, 0, hash_fingerprint);

        free(hash_fingerprint);
        fclose(logFile);

        return (*original_fwrite)(ptr, size, nmemb, stream);
    }

    return 0;
}