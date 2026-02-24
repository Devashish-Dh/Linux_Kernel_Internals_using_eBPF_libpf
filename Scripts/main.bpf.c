#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "eventDescriptors.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// setting up maps to track process vs files independently
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB
} proc_events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 25); //32 MB
} file_events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 15); // 32k entries
    __type(key, u32);           // Key: tid (unique per thread)
    __type(value, char[128]);   // Value: the path to the file 
} tmp_path SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 15); // 32k entries
    __type(key, u64);             // tgid << 32 | fd
    __type(value, char[128]);     // store file path
} track_files SEC(".maps");

/*
RingBuffer : proc_events_map, file_events_map
Hash : tmp_path, track_files
*/

/*
function names : 
    handle_proc_exit
    handle_proc_create

    handle_openat_entry
    handle_openat_exit
    handle_close_entry
*/


// processes events :

SEC("tp/sched/sched_process_exit")
int handle_proc_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct proc_log *exit_event;
	u64 id = bpf_get_current_pid_tgid(); // get PID and TID of exiting thread/process 

    __u32 tgid = id >> 32;        // main process
    __u32 tid  = id & 0xFFFFFFFF; // current thread ID

	if (tgid != tid) // ignore thread exits 
		return 0;

	exit_event = bpf_ringbuf_reserve(&proc_events_map, sizeof(*exit_event), 0); // reserve sample from BPF ringbuf 
	if (!exit_event)
		return 0;

    __builtin_memset(exit_event, 0, sizeof(*exit_event)); // init the struct 

    exit_event->tgid = tgid;  // main process
    exit_event->tid  = tid;   // exiting thread
    exit_event->pid  = 0;     // not needed for exits (it is for child processes)
    exit_event->event = PROC_EXIT;

	bpf_get_current_comm(&exit_event->progName, sizeof(exit_event->progName));// et process name 

	bpf_ringbuf_submit(exit_event, 0); // send data to user-space for post-processing 

	return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_proc_create(struct trace_event_raw_sched_process_fork* ctx)
{
    struct proc_log *create_event;
    u64 id = bpf_get_current_pid_tgid();// get PID and TID of calling thread/process 

    __u32 parent_tgid = id >> 32;        // main process
    __u32 parent_tid  = id & 0xFFFFFFFF; // current thread ID
   
    // for sched_process_fork, child_pid is the TID of the new task 
    __u32 child_pid = ctx->child_pid; 
    
    create_event = bpf_ringbuf_reserve(&proc_events_map, sizeof(*create_event), 0);
    if (!create_event)
        return 0;

    __builtin_memset(create_event, 0, sizeof(*create_event)); // init the struct

    create_event->tgid = parent_tgid; // caller PID
    create_event->tid = parent_tid;   // caller TID
    create_event->pid = child_pid;    // !!! child PID
    create_event->event = PROC_CREATE;

    bpf_get_current_comm(&create_event->progName, sizeof(create_event->progName)); // get process namce 

    bpf_ringbuf_submit(create_event, 0);
    return 0;
}


SEC("tp/syscalls/sys_enter_execve")
int handle_prog_exec(struct trace_event_raw_sys_enter* ctx)
{
    //for debugging :
    char msg[] = "EXEC TRIGGERED";
    bpf_trace_printk(msg, sizeof(msg));

    struct proc_log *exec_event;
    u64 id = bpf_get_current_pid_tgid(); // get PID and TID of exiting thread/process 

    __u32 tgid = id >> 32;        // main process
    __u32 tid  = id & 0xFFFFFFFF; // current thread ID

    exec_event = bpf_ringbuf_reserve(&proc_events_map, sizeof(*exec_event), 0);
    if (!exec_event)
        return 0;

    __builtin_memset(exec_event, 0, sizeof(*exec_event));

    exec_event->tgid = tgid; // caller PID
    exec_event->tid = tid;   // caller TID
    exec_event->pid = tgid;  // In exec, PID = TGID because this is a program execution
    exec_event->event = PROG_EXEC; 

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&exec_event->progName, sizeof(exec_event->progName), filename_ptr);

    bpf_ringbuf_submit(exec_event, 0);
    return 0;
}







// file events :
#define O_CREAT 0100 // need it for file events differentiation (in octal here)

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_entry(struct trace_event_raw_sys_enter* ctx)
{
    struct file_log *file_event;

    u64 id = bpf_get_current_pid_tgid();// get PID and TID of calling thread/process 
    __u32 tgid = id >> 32;        // main process
    __u32 tid  = id & 0xFFFFFFFF; // current thread ID

    file_event = bpf_ringbuf_reserve(&file_events_map, sizeof(*file_event), 0);
    if (!file_event)
        return 0;

    __builtin_memset(file_event, 0, sizeof(*file_event)); // init struct

    file_event->tgid = tgid;
    file_event->tid = tid;
    
    // have to check flags (3rd argument = args[2]) to determine if it's a CREATE or OPEN
    u32 flags = (u32)ctx->args[2];
    if (flags & O_CREAT) {
        file_event->event = FILE_CREATE;
    } else {
        file_event->event = FILE_OPEN;
    }

    bpf_get_current_comm(&file_event->progName, sizeof(file_event->progName)); // get process name 

    // have to read string (the file path) (2nd argument: args[1] is the pointer to the string) // will get truncated if goes beyond 128 chars
    const char *path_ptr = (const char *)ctx->args[1];
    long ret;

    ret = bpf_probe_read_user_str(&file_event->filePath, sizeof(file_event->filePath), path_ptr); // error handling just in case
    if (ret < 0) {
    char fault_msg[] = "fault/unknown";
    __builtin_memcpy(file_event->filePath, fault_msg, sizeof(fault_msg));
    }

    // have to record the file in the hash map for close() to gets its name
    bpf_map_update_elem(&tmp_path, &tid, &file_event->filePath, BPF_ANY); // fd(file descriptor) not returned need to trace the post-syscall handler too

    bpf_ringbuf_submit(file_event, 0);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit* ctx) {

    int fd = (int)ctx->ret;
    if (fd < 0) return 0; // the open() failed, skip this

    u64 id = bpf_get_current_pid_tgid();// get PID and TID of calling thread/process 
    __u32 tgid = id >> 32;        // main process
    __u32 tid  = id & 0xFFFFFFFF; // current thread ID

    // get the path saved when 'enter' was done
    char *path = bpf_map_lookup_elem(&tmp_path, &tid); // path is a global var here, funcation cans 
    if (path) { // move to the tracked hashmap only if open was successful
        u64 key = ((u64)tgid << 32) | (u32)fd;
        bpf_map_update_elem(&track_files, &key, path, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_path, &tid); // clean up temp entry in all cases

    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close_entry(struct trace_event_raw_sys_enter* ctx)
{
    struct file_log *file_event;
    u64 id = bpf_get_current_pid_tgid();// get PID and TID of calling thread/process 
    __u32 tgid = id >> 32;        // main process
    __u32 tid  = id & 0xFFFFFFFF; // current thread ID
    u32 fd = (u32)ctx->args[0]; // the FD(file descriptor) being closed
    u64 key = ((u64)tgid << 32) | (u32)fd;

    file_event = bpf_ringbuf_reserve(&file_events_map, sizeof(*file_event), 0);
    if (!file_event)
        return 0;

    __builtin_memset(file_event, 0, sizeof(*file_event));

    file_event->tgid = tgid;
    file_event->tid = tid;
    file_event->event = FILE_CLOSE;
    bpf_get_current_comm(&file_event->progName, sizeof(file_event->progName));

    // lookup the filename we stored during openat_exit
    char *path = bpf_map_lookup_elem(&track_files, &key);
    if (path) {
        // have to use kernel_str because 'path' is in a BPF map (kernel memory)
        bpf_probe_read_kernel_str(&file_event->filePath, sizeof(file_event->filePath), path);
        // clean up to prevent long-term orphans
        bpf_map_delete_elem(&track_files, &key);
    } else {
        char msg[] = "unknown/not-tracked";
        __builtin_memcpy(file_event->filePath, msg, sizeof(msg));
    }

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}