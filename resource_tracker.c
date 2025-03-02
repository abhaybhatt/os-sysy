// resource_tracker.c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/resource_tracker.h>

// Head of the monitored process list
LIST_HEAD(monitored_list);
DEFINE_MUTEX(list_lock);
int monitored_process_count; = 0;

// Register a process for monitoring
SYSCALL_DEFINE1(register_process, pid_t, pid) {
    struct task_struct *task;
    struct pid_node *new_node, *entry;
    
    if (pid < 1)
    {
        pr_info("pid < 1\n");
        return -22;  // Invalid PID
    }
        
    
    task = find_task_by_vpid(pid);
    if (!task){
        pr_info("invalid task\n");
        return -3;  // Process not found
    }
        
    
    mutex_lock(&list_lock);
    list_for_each_entry(entry, &monitored_list, list) {
        if (entry->proc_resource.pid == pid) {
            mutex_unlock(&list_lock);
            pr_info("task already in monitered list\n");
            return -23;  // Already registered
        }
    }
    
    new_node = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
    if (!new_node) {
        mutex_unlock(&list_lock);
        pr_info("task already in monitered list\n");
        return -ENOMEM;
    }
    
    new_node->proc_resource.pid = pid;
    new_node->proc_resource.heapsize = 0;
    new_node->proc_resource.openfile_count = 0;
    list_add_tail(&new_node->list, &monitored_list);
    monitored_process_count++; // Increment process count
    printk(KERN_INFO "Process %d registered. Total monitored processes: %d\n", pid, monitored_process_count);
    mutex_unlock(&list_lock);
    
    return 0;
}
