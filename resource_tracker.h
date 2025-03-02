// resource_tracker.h
#ifndef RESOURCE_TRACKER_H
#define RESOURCE_TRACKER_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

// Data structure to track process resource usage
struct per_proc_resource {
    pid_t pid;  // Process ID
    unsigned long heapsize;  // Heap memory allocated (in bytes)
    unsigned long openfile_count;  // Number of open files
};

// Node for doubly linked list using struct list_head
struct pid_node {
    struct per_proc_resource proc_resource;
    struct list_head list; // Doubly linked list node
};

extern struct list_head monitored_list;
extern struct mutex list_lock;
extern int monitored_process_count;

long sys_register_process(pid_t pid);

#endif // RESOURCE_TRACKER_H
