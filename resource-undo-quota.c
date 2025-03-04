#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/resource_tracker.h> 




SYSCALL_DEFINE1(resource_reset, pid_t, pid) {
    struct pid_node *entry;
    struct task_struct *task;
    struct pid *pid_struct;
    int found = 0;

    pr_info("sys_resource_reset: reseting limits for PID %d\n", pid);

    if (pid < 1) {
        pr_err("sys_resource_reset: Invalid PID %d\n", pid);
        return -EINVAL;
    }

    mutex_lock(&list_lock);
    list_for_each_entry(entry, &monitored_list, list) {
        if (entry->proc_resource.pid == pid) {
            found = 1;
            break;
        }
    }
    mutex_unlock(&list_lock);

    if (!found) {
        pr_err("sys_resource_reset: Process %d not found in monitored list\n", pid);
        return -ESRCH;
    }

    // Get task_struct from PID
    rcu_read_lock();
    // pid_struct = find_vpid(pid);
    task = find_task_by_vpid(pid);
    rcu_read_unlock();

    if (!task) {
        pr_err("sys_resource_reset: Task struct not found for PID %d\n", pid);
        return -ESRCH;
    }

    // Store the quota in task_struct
    task->heap_quota = -1;
    task->file_quota = -1;

    pr_info("sys_resource_reset: Limits reset for PID %d\n", pid);

    return 0;
}
