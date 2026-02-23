#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "eventDescriptors.h"


/*
function names : 
    handle_proc_exit
    handle_proc_create

    handle_openat_entry
    handle_openat_exit
    handle_close_entry
*/

#define MAX_LINKS 5

static int handle_event(void *ctx, void *data, size_t data_sz) {
    // since file struct has one more field and both have exact same layout for data...

    struct proc_log *e = data;

    if (e->event == PROC_CREATE || e->event == PROC_EXIT) {
        struct proc_log *p = data;
        const char *type = (p->event == PROC_CREATE) ? "PROC_CREATE" : "PROC_EXIT";
        
        // for  PROC_CREATE have to use p->pid (child) for PROC_EXIT have to use p->tgid (exiting process)
        int display_pid = (p->event == PROC_CREATE) ? p->pid : p->tgid;
        printf("LLT007> %s %d\n", type, display_pid);
    } 
    else if (e->event >= FILE_OPEN) {
        struct file_log *p = data;

        // skip printing if the filePath is "unknown/not-tracked"
        if (strcmp(p->filePath, "unknown/not-tracked") == 0) {
            return 0;
        }

        const char *type = (p->event == FILE_OPEN) ? "FILE_OPEN" : 
                           (p->event == FILE_CREATE) ? "FILE_CREATE" : "FILE_CLOSE";
        
        printf("LLT007> %s %d %s\n", type, p->tgid, p->filePath);
    }

    return 0;
}


int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[MAX_LINKS] = {0};
    int link_index = 0;
    int err;

    // open the BPF object file
    obj = bpf_object__open_file("main.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        return 1;
    }

    // attach handle_proc_exit
    prog = bpf_object__find_program_by_name(obj, "handle_proc_exit");
    if (prog) {
        links[link_index] = bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit");
        if (!links[link_index]) {
            fprintf(stderr, "WARNING: failed to attach handle_proc_exit\n");
        } else {
            link_index++;
        }
    } else {
        fprintf(stderr, "WARNING: program handle_proc_exit not found\n");
    }

    // attach handle_proc_create
    prog = bpf_object__find_program_by_name(obj, "handle_proc_create");
    if (prog) {
        links[link_index] = bpf_program__attach_tracepoint(prog, "sched", "sched_process_fork");
        if (!links[link_index]) {
            fprintf(stderr, "WARNING: failed to attach handle_proc_create\n");
        } else {
            link_index++;
        }
    } else {
        fprintf(stderr, "WARNING: program handle_proc_create not found\n");
    }

    // attach handle_openat_entry
    prog = bpf_object__find_program_by_name(obj, "handle_openat_entry");
    if (prog) {
        links[link_index] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_openat");
        if (!links[link_index]) {
            fprintf(stderr, "WARNING: failed to attach handle_openat_entry\n");
        } else {
            link_index++;
        }
    } else {
        fprintf(stderr, "WARNING: program handle_openat_entry not found\n");
    }

    // attach handle_openat_exit
    prog = bpf_object__find_program_by_name(obj, "handle_openat_exit");
    if (prog) {
        links[link_index] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_openat");
        if (!links[link_index]) {
            fprintf(stderr, "WARNING: failed to attach handle_openat_exit\n");
        } else {
            link_index++;
        }
    } else {
        fprintf(stderr, "WARNING: program handle_openat_exit not found\n");
    }

    // attach handle_close_entry
    prog = bpf_object__find_program_by_name(obj, "handle_close_entry");
    if (prog) {
        links[link_index] = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_close");
        if (!links[link_index]) {
            fprintf(stderr, "WARNING: failed to attach handle_close_entry\n");
        } else {
            link_index++;
        }
    } else {
        fprintf(stderr, "WARNING: program handle_close_entry not found\n");
    }

    printf("BPF programs attached. Press Ctrl+C to exit.\n");

    // get map fds
    int proc_map_fd = bpf_object__find_map_fd_by_name(obj, "proc_events_map");
    int file_map_fd = bpf_object__find_map_fd_by_name(obj, "file_events_map");

    if (proc_map_fd < 0 || file_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find ring buffer maps\n");
        return 1;
    }

    // create a manager with the first map
    struct ring_buffer *rb = ring_buffer__new(proc_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // add the second map to the same manager
    err = ring_buffer__add(rb, file_map_fd, handle_event, NULL);
    if (err < 0) {
        fprintf(stderr, "Failed to add second map to ring buffer\n");
        ring_buffer__free(rb);
        return 1;
    }

    // poll once for all managed maps
    while (1) {
        // wakes up if data arrives in EITHER proc_map or file_map
        ring_buffer__poll(rb, 100);
    }

    // clean up links
    for (int i = 0; i < link_index; i++)
        bpf_link__destroy(links[i]);

    bpf_object__close(obj);
    return 0;
}