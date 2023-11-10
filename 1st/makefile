all:
		gcc main.c -o main
		gcc -w -Wall -fPIC -shared -o logger_lib.so logger_lib.c -lcrypto
		LD_PRELOAD=./logger_lib.so ./main