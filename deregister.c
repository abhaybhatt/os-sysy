#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/resource_tracker.h> 

SYSCALL_DEFINE1(deregister, pid_t, pid) {
    pr_info("inside deregister with %d\n", pid);
    struct pid_node *entry, *temp;
    int found = 0;

    if (pid < 1) {
        pr_err("sys_deregister: Invalid PID %d\n", pid);
        return -EINVAL;
    }

    mutex_lock(&list_lock);
    list_for_each_entry_safe(entry, temp, &monitored_list, list) {
        if (entry->proc_resource.pid == pid) {
            list_del(&entry->list);  // Remove from linked list
            kfree(entry);  // Free memory
            monitored_process_count--;
            found = 1;
            pr_info("sys_deregister: Successfully removed PID %d. Remaining monitored: %d\n",
                    pid, monitored_process_count);
            break;
        }
    }
    mutex_unlock(&list_lock);

    if (!found) {
        pr_err("sys_deregister: Process %d not found in monitored list\n", pid);
        return -ESRCH;
    }

    return 0;
}
