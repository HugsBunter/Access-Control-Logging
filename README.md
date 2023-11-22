# Access Control Logging & Log Monitoring Tools

This repository contains tools to test Access Control Logging and Log Monitoring functionalities.

### Build and Usage Instructions

To build the project, follow these steps:

```bash
make all
```

This command generates all the necessary files for testing.

To lock all files and then attempt to access them:

```bash
make lock
```

To unlock the locked files, access them, and make changes:

```bash
make unlock
```

To build the Access Control Monitoring tool:

```bash
make acmonitortool
```

### Accesing Tools

To view the uids of all the malicious users:

```bash
./acmonitor -m
```

To obtain modification information for a specific file path:

```bash
./acmonitor -i [filepath]
```

Keep in mind to provide the complete file path for the tool to run correctly. For example:

```bash
./acmonitor -i /home/niki/Desktop/assign_2/test_2.txt
```

To run only the test_aclog:

```bash
./test_aclog -[X]
```

Where 'X' can be:
- 'm' (to make the files)
- 'l' (to lock the files)
- 'u' (to unlock the files)

### Clean Up

To clean up generated files:

```bash
make clean
```

### Tips for Running and Testing

1. Run "make all" for the first time.
2. Run "make lock" and/or "make unlock" in any order, multiple times as needed.
3. Use "make lock" multiple times to simulate malicious users and file modifications.
4. Run "make acmonitortool" to utilize the access monitor tool and then use it.

Example: To view modifications for 'test_4.txt' (the most frequently modified file):

```bash
./acmonitor -i /home/niki/Desktop/assign_2/test_4.txt
```

5. Once done, execute "make clean".

### Additional Note

If you wish to test with the 'getuid' function, modify the 'logger.c' file:
- Comment out the random function (lines 51, 52).
- Uncomment the 'getuid' function.
