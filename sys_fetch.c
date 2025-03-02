#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>        // Memory tracking
#include <linux/fs.h>        // File descriptor tracking
#include <linux/fdtable.h>   // File descriptor table
#include <linux/mutex.h>
#include <linux/uaccess.h>   // For copy_to_user
#include <linux/pid.h>       // For find_vpid
#include <linux/rcupdate.h>  // For rcu_read_lock

#include <linux/resource_tracker.h> 

// Function to calculate heap size dynamically
static unsigned long calculate_heap_size(struct task_struct *task) {
    struct mm_struct *mm;
    unsigned long heap_size = 0;

    if (!task)
        return 0;

    mm = get_task_mm(task);
    if (!mm)
        return 0;

    // Heap size = (brk - start_brk) + mapped memory regions
    heap_size = (mm->brk - mm->start_brk) + mm->total_vm * PAGE_SIZE;

    mmput(mm);  // Release mm_struct
    return heap_size / (1024 * 1024);  // Convert to MB
}

// Function to count open files dynamically
static unsigned long count_open_files(struct task_struct *task) {
    struct files_struct *files;
    struct fdtable *fdt;
    unsigned long open_files = 0;
    int i;

    if (!task)
        return 0;

    files = task->files;
    if (!files)
        return 0;

    rcu_read_lock();  // Protect access to file descriptor table
    fdt = files_fdtable(files);

    for (i = 0; i < fdt->max_fds; i++) {
        if (fdt->fd[i])  // Count valid file descriptors
            open_files++;
    }

    rcu_read_unlock();
    return open_files;
}

SYSCALL_DEFINE2(fetch, struct per_proc_resource __user *, stats, pid_t, pid) {
    struct pid_node *entry;
    struct task_struct *task;
    struct per_proc_resource temp_resource;
    // struct pid *pid_struct;
    int found = 0;
    pr_info("inside call of fetch");
    pr_info("sys_fetch pid in arg:%d\n", pid);
    if (pid < 1) {
        pr_err("sys_fetch: Invalid PID %d\n", pid);
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
        pr_err("sys_fetch: Process %d not found in monitored list\n", pid);
        return -EINVAL;
    }

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        pr_err("sys_fetch: No valid struct pid found for PID %d\n", pid);
        return -ESRCH;
    }

    // task = pid_task(pid_struct, PIDTYPE_PID);
    // task = pid_task(pid_struct, PIDTYPE_PID);
    rcu_read_unlock();

    if (!task) {
        pr_err("sys_fetch: Task struct not found for PID %d\n", pid);
        return -ESRCH;
    }

    temp_resource.pid = pid;
    temp_resource.heapsize = calculate_heap_size(task);
    temp_resource.openfile_count = count_open_files(task);

    if (copy_to_user(stats, &temp_resource, sizeof(struct per_proc_resource))) {
        pr_err("sys_fetch: Failed to copy data to user\n");
        return -EFAULT;
    }

    pr_info("sys_fetch: PID %d - Heap: %lu KB, Open Files: %lu\n",
            pid, temp_resource.heapsize / 1024, temp_resource.openfile_count);

    return 0;
}
