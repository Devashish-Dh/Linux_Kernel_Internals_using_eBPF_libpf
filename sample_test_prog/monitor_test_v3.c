#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

/**
 * AI generated : COMPREHENSIVE TEST SUITE V3
 * Simulates : Process Creation (Fork), Execution (Exec), 
 * File Ops (Open/Write/Read/Close), and Process Exit (Kill).
 */

void create_victim_source() {
    FILE *f = fopen("victim.c", "w");
    if (f) {
        fprintf(f, "#include <stdio.h>\n#include <unistd.h>\nint main() { while(1) sleep(1); return 0; }\n");
        fclose(f);
        // Compile a separate binary to trigger EXECVE identity change
        if (system("gcc victim.c -o victim_bin") != 0) {
            fprintf(stderr, "Failed to compile victim_bin\n");
        }
    }
}

int main() {
    pid_t my_pid = getpid();
    char *test_file = "ebpf_test_file.txt";
    char *test_dir = "ebpf_test_dir";
    int iteration = 1;

    printf("==========================================\n");
    printf(" MONITOR TEST SUITE V3\n");
    printf(" MAIN PID: %d\n", my_pid);
    printf("==========================================\n\n");

    create_victim_source();

    while (1) {
        printf("[%d] --- STARTING CYCLE %d ---\n", my_pid, iteration++);

        // 1. FORK & EXEC TEST (PROC_CREATE & EXECVE)
        printf("[%d] ACTION: Forking child process...\n", my_pid);
        pid_t child_pid = fork();

        if (child_pid == 0) {
            // In Child: Transform into victim_bin
            char *args[] = {"./victim_bin", NULL};
            execv(args[0], args);
            exit(0); 
        } 

        // In Parent: Continue with other tests while child runs
        printf("[%d] FORK SUCCESS: Child PID is %d\n", my_pid, child_pid);

        // 2. FILE OPEN/WRITE TEST (FILE_OPEN / FILE_CREATE)
        printf("[%d] ACTION: Creating/Writing to %s\n", my_pid, test_file);
        int fd = open(test_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd != -1) {
            write(fd, "eBPF test data\n", 15);
            
            // 3. FILE CLOSE TEST (FILE_CLOSE)
            printf("[%d] ACTION: Closing %s\n", my_pid, test_file);
            close(fd);
        }

        // 4. DIRECTORY TEST (MKDIR/RMDIR)
        printf("[%d] ACTION: Mkdir/Rmdir %s\n", my_pid, test_dir);
        mkdir(test_dir, 0755);
        rmdir(test_dir);

        // 5. FILE READ TEST
        printf("[%d] ACTION: Reading %s\n", my_pid, test_file);
        fd = open(test_file, O_RDONLY);
        if (fd != -1) {
            char buf[16];
            read(fd, buf, sizeof(buf));
            close(fd);
        }

        // 6. WAIT & KILL TEST (PROC_EXIT)
        printf("[%d] Waiting for monitor to sync...\n", my_pid);
        sleep(3);
        
        printf("[%d] ACTION: Killing child process %d\n", my_pid, child_pid);
        kill(child_pid, SIGKILL);
        wait(NULL); // Reap child to ensure PROC_EXIT triggers cleanly

        printf("[%d] --- CYCLE COMPLETE ---\n\n", my_pid);
        sleep(2);
    }

    return 0;
}
