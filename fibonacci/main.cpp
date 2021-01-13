#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

int main(int argc, char **argv)
{
    const char *path = "./fibonacci";
    const char *name = "fibonacci";
    pid_t pid;
    switch(pid = fork()) {
        case -1: /* error */
        {
            perror("fork()");
            exit(-1);
        }
        case 0: /* child process */
        {
            ptrace(PTRACE_TRACEME, NULL, NULL);
            /* allow child process to be traced */
            execl(path, name, NULL); /* child will be stopped here */
            perror("execl()");
            exit(-1);
        }
        /* parent continues execution */
    }
    int status;
    wait(&status);
    printf("status %d\n", status);
    return 0;
}