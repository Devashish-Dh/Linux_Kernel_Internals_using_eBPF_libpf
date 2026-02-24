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
 * COMPREHENSIVE TEST SUITE (AI GENERATED)
 */

void create_victim_source() {
    FILE *f = fopen("victim.c", "w");
    if (f) {
        fprintf(f, "#include <stdio.h>\n#include <unistd.h>\nint main() { printf(\"--- VICTIM RUNNING ---\\n\"); sleep(1); return 0; }\n");
        fclose(f);
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
    printf(" MONITOR TEST SUITE \n");
    printf(" MAIN PID: %d\n", my_pid);
    printf("==========================================\n\n");

    create_victim_source();

    while (1) {
        printf("[%d] --- STARTING CYCLE %d ---\n", my_pid, iteration++);

        // 1. FORK & EXEC TEST (The Binary You Compiled)
        printf("[%d] ACTION: Fork/Exec ./victim_bin\n", my_pid);
        pid_t child1 = fork();
        if (child1 == 0) {
            char *args[] = {"./victim_bin", NULL};
            execv(args[0], args);
            perror("execv failed");
            exit(1); 
        }

        // 2. SYSTEM() CALL TEST (Triggers /bin/sh then /usr/bin/whoami)
        printf("[%d] ACTION: system(\"whoami\")\n", my_pid);
        system("whoami");

        // 3. EXECLP TEST (Search PATH for 'ls')
        printf("[%d] ACTION: Fork/Execlp 'ls'\n", my_pid);
        pid_t child2 = fork();
        if (child2 == 0) {
            execlp("ls", "ls", "-l", NULL);
            exit(0);
        }
        waitpid(child2, NULL, 0);

        // 4. FILE OPERATIONS (To keep those hooks active)
        int fd = open(test_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd != -1) {
            write(fd, "eBPF test\n", 10);
            close(fd);
        }

        // 5. DIRECTORY OPERATIONS
        mkdir(test_dir, 0755);
        rmdir(test_dir);

        // 6. CLEANUP CHILD 1
        printf("[%d] ACTION: Killing child %d\n", my_pid, child1);
        kill(child1, SIGKILL);
        waitpid(child1, NULL, 0);

        printf("[%d] --- CYCLE COMPLETE ---\n\n", my_pid);
        sleep(3);
    }

    return 0;
}
