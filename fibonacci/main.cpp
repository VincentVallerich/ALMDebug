#include <iostream>
#include "symbol.h"
#include "breakpoint.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <dis-asm.h>
#include <map>
#include <string>
#include <iterator>

void disassemble(bfd_byte *buf, unsigned long size)
{
    disassemble_info dis_info;
    disassembler_ftype disassemble_func;
    init_disassemble_info (&dis_info, stdout, (fprintf_ftype)fprintf);
    dis_info.arch = bfd_arch_i386;
    dis_info.mach = bfd_mach_x86_64;
    dis_info.endian = BFD_ENDIAN_LITTLE;
    dis_info.buffer = buf;
    dis_info.buffer_length = size;
    disassemble_func = disassembler(dis_info.arch,
    (dis_info.endian == BFD_ENDIAN_BIG), dis_info.mach, NULL);
    disassemble_func(0, &dis_info);
    printf("\n");
}

std::map<std::string, Symbol> loadSymbolTable(const char *path) {
    /* Initialize Binary File Descriptor Library */
    bfd_init();
    /* Open the file and return a Binary File Descriptor */
    bfd *abfd = bfd_openr(path, NULL);
    /* Check if the file is a binary object file */
    bfd_check_format(abfd, bfd_object);
    /* Return the number of bytes required to store a vector of pointers
    for all the symbols in the BFD */
    long size = bfd_get_symtab_upper_bound(abfd);
    asymbol **asymtab = (asymbol **)malloc(size);
    /* Read the symbols from the BFD abfd, and fills in the vector location
    with pointers to the symbols and a trailing NULL.
    Return the actual number of symbol pointers, not including the NULL. */
    long nsym = bfd_canonicalize_symtab(abfd, asymtab);
    /* Create a symbol map indexed by symbol names */
    std::map<std::string, Symbol> symbolTable;
    for (long i = 0; i < nsym; i++) {
        Symbol* symbol = new Symbol(bfd_asymbol_name(asymtab[i]), bfd_asymbol_value(asymtab[i]));
        symbolTable[symbol->sym] = *symbol;
    // ➡︎ créez un objet de type Symbol dont le nom est récupéré par
    // l’expression : bfd_asymbol_name(asymtab[i]) et l’adresse par :
        // bfd_asymbol_value(asymtab[i]);
    // ➡︎ insérez cet objet dans le dictionnaire en l’associant à son nom
    }
    return symbolTable;
}

void findSymbols(std::map<std::string, Symbol> symbolTable, std::map<long, Breakpoint>* breakpointTable, std::string name) {
    if (symbolTable.find(name) != symbolTable.end()){
        Symbol symbol = symbolTable.find(name);
        /* Define new breakpoint */
        Breakpoint breakpoint;
        breakpoint.sym = symbol.sym;
        /* Save instruction at rip */
        breakpoint.opcode = ptrace(PTRACE_PEEKTEXT, pid, symbol.addr,NULL);
        /* Insert breakpoint */
        ptrace(PTRACE_POKETEXT, pid, symbol.addr, 0xcc);
        &breakpointTable[breakpoint.opcode] = *breakpoint;
        printf("breakpoint at %lx<%s>\n", symbol.addr,
        symbol.sym.c_str());
    } else {
        printf("symbol not found <%s>\n", cmdStr);
    }
}

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
    std::map<std::string, Symbol> symbolTable = loadSymbolTable(path);
    std::map<long, Breakpoint> breakpointTable;
    int status;
    wait(&status);
    std::string input;
    std::string cmd;
    std::string delimiter = " ";
    while(1) {
        if(WIFEXITED(status) || (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)) {
            printf("process %d terminated\n", pid);
            exit(0);
        }
        if(WIFSTOPPED(status)) {
            /* Get rip, subtract 1 to be (eventually) positioned on INT 3 codeop */
            long rip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL) - 1;
            /* Check if this address corresponds to a breakpoint */
            std::map<long, Breakpoint>::iterator it =
            breakpointTable.find(rip);
            if (it != breakpointTable.end()) {
                /* Encountered a breakpoint (INT 3) */
                /* Remove this break point from the table */
                breakpointTable.erase(it);
                Breakpoint breakpoint = it->second;
                /* Restore instruction */
                ptrace(PTRACE_POKETEXT, pid, rip, breakpoint.opcode);
                /* Decrement rip */
                ptrace(PTRACE_POKEUSER, pid, 8 * RIP, rip);
                printf("process %d stopped at 0x%lx<%s>\n", pid, rip,breakpoint.sym.c_str());
            } else {
                /* Stop not caused by INT 3 */
                /* Reposition rip after executed instruction */
                rip++;
                printf("process %d stopped at 0x%lx\n", pid, rip);
            }
            long opcode[2];
            opcode[0] = ptrace(PTRACE_PEEKDATA, pid, rip, NULL);
            opcode[1] = ptrace(PTRACE_PEEKDATA, pid, rip+sizeof(long),NULL);
            disassemble((bfd_byte *)opcode, 16);
            }
        /* get a command from user */
        printf("(mdb) ");
        std::cin >> input;
        cmd = input.substr(0, input.find(delimiter));
        if (cmd == "kill") {
            kill(pid, SIGKILL);
        } else if (cmd == "c") {
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        } else if (cmd == "s"){
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        } else if (cmd == "br") {
            std::cout << "salut";
            findSymbols("fibonacci");
            // std::string arg = input.substr(input.find(delimiter), input.length());
        } else {
            std::cout << "Error unknown command" << std::endl;
            continue;
        }
        wait(&status);
    }

    return 0;
}

    /* disassemble instruction(s) from buf */
    // const char* normal_exit = (WIFEXITED(status) == 0) ? "true" : "false";       
    // const char* sig_exit = (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) ? "true" : "false";
    // printf("status %d\n", status);
    // printf("normal exit : %s\n", normal_exit);
    // printf("sig exit : %s\n", sig_exit);
    // if (WIFSTOPPED(status) == 0) {
    //     long rip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);  
    //     std::cout << "Pointeur d'instruction : " << rip << std::endl;
    // }