#ifndef __COMMON_H__
#define __COMMON_H__

//#include "vmlinux.h"

enum event_type 
    {
        UNSPECIFIED = 0,
        PROC_CREATE, //1
        PROC_EXIT,   //2
        FILE_OPEN,   //3
        FILE_CLOSE,  //4
        FILE_CREATE, //5
        PROG_EXEC    //6
    };

    
struct proc_log // condition to check main process : tid == tgid 
{
    __u32 tgid; // main process id
    __u32 tid;  // actual thread that triggered the event 

    __u32 pid;  // child id (child process / thread)

    __u32 event;
    char progName[16];// alias for processes (from kernel data struct)
}; //8 byte aligned, size = 32 Bytes 


struct file_log
{
    __u32 tgid; // main process id
    __u32 tid;  // actual thread that triggered the event 

    __u32 pid;  // child id (child process / thread)

    __u32 event;
    char progName[16];
    char filePath[128]; // need the filepath not the file descriptor, need to find correct tracepoint
}; //8 byte aligned, size = 152 Bytes


#endif