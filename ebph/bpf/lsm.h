/*  ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
 *  ebpH Copyright (C) 2019-2020  William Findlay
 *  pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Provides a unique ID for each LSM program.
 *
 *  2020-Aug-04  William Findlay  Created this.
 */

enum ebph_lsm_id_t {
    EBPH_BPRM_CHECK_SECURITY = 0,
    EBPH_TASK_ALLOC,
    EBPH_TASK_FREE,
    EBPH_TASK_SETPGID,
    EBPH_TASK_GETPGID,
    EBPH_TASK_GETSID,
    EBPH_TASK_SETNICE,
    EBPH_TASK_SETIOPRIO,
    EBPH_TASK_GETIOPRIO,
    EBPH_TASK_PRLIMIT,
    EBPH_TASK_SETRLIMIT,
    EBPH_TASK_SETSCHEDULER,
    EBPH_TASK_GETSCHEDULER,
    EBPH_TASK_MOVEMEMORY,
    EBPH_TASK_KILL,  // TODO: split this into coarse signal categories
    EBPH_TASK_PRCTL,
    EBPH_SB_STATFS,
    EBPH_SB_MOUNT,
    EBPH_SB_REMOUNT,
    EBPH_SB_UMOUNT,
    EBPH_SB_PIVOTROOT,
    EBPH_MOVE_MOUNT,
    EBPH_INODE_CREATE,
    EBPH_INODE_LINK,
    EBPH_INODE_SYMLINK,
    EBPH_INODE_MKDIR,
    EBPH_INODE_RMDIR,
    EBPH_INODE_MKNOD,
    EBPH_INODE_RENAME,
    EBPH_INODE_READLINK,
    EBPH_INODE_FOLLOW_LINK,
    EBPH_INODE_PERMISSION,  // TODO: split this into READ, WRITE, APPEND, EXEC
    EBPH_INODE_SETATTR,
    EBPH_INODE_GETATTR,
    EBPH_INODE_SETXATTR,
    EBPH_INODE_GETXATTR,
    EBPH_INODE_LISTXATTR,
    EBPH_INODE_REMOVEXATTR,
    EBPH_FILE_PERMISSION,  // TODO: split this into READ, WRITE, APPEND, EXEC
    EBPH_FILE_IOCTL,
    EBPH_MMAP_ADDR,
    EBPH_MMAP_FILE,
    EBPH_FILE_MPROTECT,
    EBPH_FILE_LOCK,
    EBPH_FILE_FCNTL,
    EBPH_FILE_SEND_SIGIOTASK,
    EBPH_FILE_RECEIVE,
    EBPH_UNIX_STREAM_CONNECT,
    EBPH_UNIX_MAY_SEND,
    EBPH_SOCKET_CREATE,
    EBPH_SOCKET_SOCKETPAIR,
    EBPH_SOCKET_BIND,
    EBPH_SOCKET_CONNECT,
    EBPH_SOCKET_LISTEN,
    EBPH_SOCKET_ACCEPT,
    EBPH_SOCKET_SENDMSG,
    EBPH_SOCKET_RECVMSG,
    EBPH_SOCKET_GETSOCKNAME,
    EBPH_SOCKET_GETPEERNAME,
    EBPH_SOCKET_GETSOCKOPT,
    EBPH_SOCKET_SETSOCKOPT,
    EBPH_SOCKET_SHUTDOWN,
    EBPH_TUN_DEV_CREATE,
    EBPH_TUN_DEV_ATTACH,
    EBPH_KEY_ALLOC,
    EBPH_KEY_FREE,
    EBPH_KEY_PERMISSION,  // TODO: maybe split this into operations
    EBPH_IPC_PERMISSION,
    EBPH_MSG_QUEUE_ASSOCIATE,
    EBPH_MSG_QUEUE_MSGCTL,
    EBPH_MSG_QUEUE_MSGSND,
    EBPH_MSG_QUEUE_MSGRCV,
    EBPH_SHM_ASSOCIATE,
    EBPH_SHM_SHMCTL,
    EBPH_SHM_SHMAT,
    EBPH_PTRACE_ACCESS_CHECK,
    EBPH_PTRACE_TRACEME,
    EBPH_CAPGET,
    EBPH_CAPSET,
    EBPH_CAPABLE,
    EBPH_QUOTACTL,
    EBPH_QUOTA_ON,
    EBPH_SYSLOG,
    EBPH_SETTIME,
    EBPH_VM_ENOUGH_MEMORY,
    EBPH_BPF,
    EBPH_BPF_MAP,
    EBPH_BPF_PROG,
    EBPH_PERF_EVENT_OPEN,
    EBPH_LSM_MAX,  // This must always be the last entry
};
