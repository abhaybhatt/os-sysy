#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/resource_tracker.h> 




SYSCALL_DEFINE3(resource_cap, pid_t, pid, long, heap_quota, long, file_quota) {
    struct pid_node *entry;
    struct task_struct *task;
    struct pid *pid_struct;
    int found = 0;

    pr_info("sys_resource_cap: Setting limits for PID %d - Heap: %ld MB, Files: %ld\n",
            pid, heap_quota, file_quota);

    if (pid < 1) {
        pr_err("sys_resource_cap: Invalid PID %d\n", pid);
        return -EINVAL;
    }

    if (heap_quota < -1 || file_quota < -1) {
        pr_err("sys_resource_cap: Invalid quota values for PID %d\n", pid);
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
        pr_err("sys_resource_cap: Process %d not found in monitored list\n", pid);
        return -ESRCH;
    }

    // Get task_struct from PID
    rcu_read_lock();
    // pid_struct = find_vpid(pid);
    task = find_task_by_vpid(pid);
    rcu_read_unlock();

    if (!task) {
        pr_err("sys_resource_cap: Task struct not found for PID %d\n", pid);
        return -ESRCH;
    }

    // Store the quota in task_struct
    task->heap_quota = (heap_quota == -1) ? LONG_MAX : heap_quota;
    task->file_quota = (file_quota == -1) ? LONG_MAX : file_quota;

    pr_info("sys_resource_cap: Limits set in task_struct for PID %d - Heap: %ld MB, Files: %ld\n",
            pid, task->heap_quota, task->file_quota);

    return 0;
}
