all:
		gcc test_aclog.c -o test_aclog
		gcc -w -Wall -fPIC -shared -o logger.so logger.c -lcrypto
		LD_PRELOAD=./logger.so ./test_aclog -m
lock:
		gcc test_aclog.c -o test_aclog
		gcc -w -Wall -fPIC -shared -o logger.so logger.c -lcrypto
		LD_PRELOAD=./logger.so ./test_aclog -l 
unlock:
		gcc test_aclog.c -o test_aclog
		gcc -w -Wall -fPIC -shared -o logger.so logger.c -lcrypto
		LD_PRELOAD=./logger.so ./test_aclog -u 
acmonitortool:
		gcc acmonitor.c -o acmonitor
clean:
		rm -rf test_aclog
		rm -rf acmonitor
