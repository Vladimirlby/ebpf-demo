// helloworld.bpf.c 

#include <vmlinux.h>
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int count = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);//pid
	__type(value, u64);//time
} syscall_times SEC(".maps");


/*
SEC("tracepoint/syscalls/sys_enter_execve")

int bpf_prog(void *ctx) {
  char msg[] = "Hello, World!";
  bpf_printk("invoke bpf_prog: %s\n", msg);
  return 0;
}*/

/*
SEC("tracepoint/syscalls/sys_enter_open")
int bpf_enter_open(void* ctx){
    u64 timestamp = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    bpf_map_update_elem(&syscall_times, &pid, &timestamp, BPF_ANY);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_open")
int bpf_exit_open(void* ctx){
    u64 *prev_time, delta;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >>32;
    u32 pid = id; 
    prev_time = bpf_map_lookup_elem(&syscall_times, &pid);
    if (prev_time) {
        delta = bpf_ktime_get_ns() - *prev_time;
        bpf_printk("Open syscall took %llu ns\n", delta);
    }
    return 0;
}
*/

SEC("tracepoint/syscalls/sys_enter_read")
int bpf_enter_read(void* ctx){
    u64 timestamp = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    count++;
    bpf_map_update_elem(&syscall_times, &pid, &timestamp, BPF_ANY);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int bpf_exit_read(void* ctx){
    u64 *prev_time, delta;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    prev_time = bpf_map_lookup_elem(&syscall_times, &pid);
    if (prev_time) {
        delta = bpf_ktime_get_ns() - *prev_time;
        bpf_printk("pid: %d   Read syscall took %llu ns\n",pid, delta);   
    }
    bpf_printk("the count of syscall--read : %d\n",count);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
/*

syscalls:sys_exit_read
syscalls:sys_enter_read

syscalls:sys_exit_write
syscalls:sys_enter_write

syscalls:sys_exit_openat2
syscalls:sys_enter_openat2

syscalls:sys_exit_openat
syscalls:sys_enter_openat

syscalls:sys_exit_open
syscalls:sys_enter_open

syscalls:sys_exit_setfsgid
syscalls:sys_enter_setfsgid
syscalls:sys_exit_setfsuid
syscalls:sys_enter_setfsuid

syscalls:sys_exit_pidfd_getfd
syscalls:sys_enter_pidfd_getfd
syscalls:sys_exit_pidfd_open
syscalls:sys_enter_pidfd_open

syscalls:sys_exit_close
syscalls:sys_enter_close
syscalls:sys_exit_creat
syscalls:sys_enter_creat

syscalls:sys_exit_fchown
syscalls:sys_enter_fchown
syscalls:sys_exit_lchown
syscalls:sys_enter_lchown
syscalls:sys_exit_chown
syscalls:sys_enter_chown
syscalls:sys_exit_fchownat
syscalls:sys_enter_fchownat
syscalls:sys_exit_chmod
syscalls:sys_enter_chmod
syscalls:sys_exit_fchmodat
syscalls:sys_enter_fchmodat
syscalls:sys_exit_fchmod
syscalls:sys_enter_fchmod
syscalls:sys_exit_chroot
syscalls:sys_enter_chroot
syscalls:sys_exit_fchdir
syscalls:sys_enter_fchdir

syscalls:sys_exit_access
syscalls:sys_enter_access
syscalls:sys_exit_faccessat2
syscalls:sys_enter_faccessat2
syscalls:sys_exit_faccessat
syscalls:sys_enter_faccessat
syscalls:sys_exit_fallocate
syscalls:sys_enter_fallocate
syscalls:sys_exit_ftruncate
syscalls:sys_enter_ftruncate
syscalls:sys_exit_truncate
syscalls:sys_enter_truncate

syscalls:sys_exit_sendfile64
syscalls:sys_enter_sendfile64
syscalls:sys_exit_pwritev2
syscalls:sys_enter_pwritev2
syscalls:sys_exit_pwritev
syscalls:sys_enter_pwritev
syscalls:sys_exit_preadv2
syscalls:sys_enter_preadv2
syscalls:sys_exit_preadv
syscalls:sys_enter_preadv
syscalls:sys_exit_writev
syscalls:sys_enter_writev
syscalls:sys_exit_readv
syscalls:sys_enter_readv
syscalls:sys_exit_pwrite64
syscalls:sys_enter_pwrite64
syscalls:sys_exit_pread64
syscalls:sys_enter_pread64


syscalls:sys_exit_copy_file_range
syscalls:sys_enter_copy_file_range

syscalls:sys_exit_lseek
syscalls:sys_enter_lseek
syscalls:sys_exit_statx
syscalls:sys_enter_statx
syscalls:sys_exit_readlink
syscalls:sys_enter_readlink
syscalls:sys_exit_readlinkat
syscalls:sys_enter_readlinkat
syscalls:sys_exit_newfstat
syscalls:sys_enter_newfstat
syscalls:sys_exit_newfstatat
syscalls:sys_enter_newfstatat
syscalls:sys_exit_newlstat
syscalls:sys_enter_newlstat
syscalls:sys_exit_newstat
syscalls:sys_enter_newstat


syscalls:sys_exit_rename
syscalls:sys_enter_rename
syscalls:sys_exit_renameat
syscalls:sys_enter_renameat
syscalls:sys_exit_renameat2
syscalls:sys_enter_renameat2

syscalls:sys_exit_link
syscalls:sys_enter_link
syscalls:sys_exit_linkat
syscalls:sys_enter_linkat
syscalls:sys_exit_symlink
syscalls:sys_enter_symlink
syscalls:sys_exit_symlinkat
syscalls:sys_enter_symlinkat
syscalls:sys_exit_unlink
syscalls:sys_enter_unlink
syscalls:sys_exit_unlinkat
syscalls:sys_enter_unlinkat
syscalls:sys_exit_rmdir
syscalls:sys_enter_rmdir
syscalls:sys_exit_mkdir
syscalls:sys_enter_mkdir
syscalls:sys_exit_mkdirat
syscalls:sys_enter_mkdirat
syscalls:sys_exit_mknod
syscalls:sys_enter_mknod
syscalls:sys_exit_mknodat
syscalls:sys_enter_mknodat

syscalls:sys_exit_fcntl
syscalls:sys_enter_fcntl
syscalls:sys_exit_ioctl
syscalls:sys_enter_ioctl
syscalls:sys_exit_getdents64
syscalls:sys_enter_getdents64
syscalls:sys_exit_getdents
syscalls:sys_enter_getdents
syscalls:sys_exit_ppoll
syscalls:sys_enter_ppoll
syscalls:sys_exit_poll
syscalls:sys_enter_poll
syscalls:sys_exit_pselect6
syscalls:sys_enter_pselect6
syscalls:sys_exit_select
syscalls:sys_enter_select

yscalls:sys_exit_dup
syscalls:sys_enter_dup
syscalls:sys_exit_dup2
syscalls:sys_enter_dup2
syscalls:sys_exit_dup3
syscalls:sys_enter_dup3
syscalls:sys_exit_sysfs
syscalls:sys_enter_sysfs
syscalls:sys_exit_mount_setattr
syscalls:sys_enter_mount_setattr
syscalls:sys_exit_pivot_root
syscalls:sys_enter_pivot_root
syscalls:sys_exit_move_mount
syscalls:sys_enter_move_mount
syscalls:sys_exit_fsmount
syscalls:sys_enter_fsmount
syscalls:sys_exit_mount
syscalls:sys_enter_mount
syscalls:sys_exit_open_tree
syscalls:sys_enter_open_tree
syscalls:sys_exit_umount
syscalls:sys_enter_umount
syscalls:sys_exit_fremovexattr
syscalls:sys_enter_fremovexattr
syscalls:sys_exit_lremovexattr
syscalls:sys_enter_lremovexattr
syscalls:sys_exit_removexattr
syscalls:sys_enter_removexattr
syscalls:sys_exit_flistxattr
syscalls:sys_enter_flistxattr
syscalls:sys_exit_llistxattr
syscalls:sys_enter_llistxattr
syscalls:sys_exit_listxattr
syscalls:sys_enter_listxattr
syscalls:sys_exit_fgetxattr
syscalls:sys_enter_fgetxattr
syscalls:sys_exit_lgetxattr
syscalls:sys_enter_lgetxattr
syscalls:sys_exit_getxattr
syscalls:sys_enter_getxattr
syscalls:sys_exit_fsetxattr
syscalls:sys_enter_fsetxattr
syscalls:sys_exit_lsetxattr
syscalls:sys_enter_lsetxattr
syscalls:sys_exit_setxattr
syscalls:sys_enter_setxattr

syscalls:sys_exit_tee
syscalls:sys_enter_tee
syscalls:sys_exit_splice
syscalls:sys_enter_splice
syscalls:sys_exit_vmsplice
syscalls:sys_enter_vmsplice
syscalls:sys_exit_sync_file_range
syscalls:sys_enter_sync_file_range
syscalls:sys_exit_fdatasync
syscalls:sys_enter_fdatasync
syscalls:sys_exit_fsync
syscalls:sys_enter_fsync
syscalls:sys_exit_syncfs
syscalls:sys_enter_syncfs

syscalls:sys_exit_sync
syscalls:sys_enter_sync
syscalls:sys_exit_utime
syscalls:sys_enter_utime
syscalls:sys_exit_utimes
syscalls:sys_enter_utimes
syscalls:sys_exit_futimesat
syscalls:sys_enter_futimesat
syscalls:sys_exit_utimensat
syscalls:sys_enter_utimensat
syscalls:sys_exit_getcwd
syscalls:sys_enter_getcwd
syscalls:sys_exit_ustat
syscalls:sys_enter_ustat
syscalls:sys_exit_fstatfs
syscalls:sys_enter_fstatfs
syscalls:sys_exit_statfs
syscalls:sys_enter_statfs
syscalls:sys_exit_fsconfig
syscalls:sys_enter_fsconfig
syscalls:sys_exit_fspick
syscalls:sys_enter_fspick
syscalls:sys_exit_fsopen
syscalls:sys_enter_fsopen
syscalls:sys_exit_inotify_rm_watch
syscalls:sys_enter_inotify_rm_watch
syscalls:sys_exit_inotify_add_watch
syscalls:sys_enter_inotify_add_watch
syscalls:sys_exit_inotify_init
syscalls:sys_enter_inotify_init
syscalls:sys_exit_inotify_init1
syscalls:sys_enter_inotify_init1
syscalls:sys_exit_fanotify_mark
syscalls:sys_enter_fanotify_mark
syscalls:sys_exit_fanotify_init
syscalls:sys_enter_fanotify_init
syscalls:sys_exit_epoll_pwait2
syscalls:sys_enter_epoll_pwait2
syscalls:sys_exit_epoll_pwait
syscalls:sys_enter_epoll_pwait
syscalls:sys_exit_epoll_wait
syscalls:sys_enter_epoll_wait
syscalls:sys_exit_epoll_ctl
syscalls:sys_enter_epoll_ctl
syscalls:sys_exit_epoll_create
syscalls:sys_enter_epoll_create
syscalls:sys_exit_epoll_create1
syscalls:sys_enter_epoll_create1
syscalls:sys_exit_signalfd
syscalls:sys_enter_signalfd
syscalls:sys_exit_signalfd4
syscalls:sys_enter_signalfd4
syscalls:sys_exit_timerfd_gettime
syscalls:sys_enter_timerfd_gettime
syscalls:sys_exit_timerfd_settime
syscalls:sys_enter_timerfd_settime
syscalls:sys_exit_timerfd_create
syscalls:sys_enter_timerfd_create
syscalls:sys_exit_eventfd
syscalls:sys_enter_eventfd
syscalls:sys_exit_eventfd2
syscalls:sys_enter_eventfd2
syscalls:sys_exit_userfaultfd
syscalls:sys_enter_userfaultfd
*/
