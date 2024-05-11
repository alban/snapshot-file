// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef KSYM_NAME_LEN
#define KSYM_NAME_LEN 512
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct {
	const char name[KSYM_NAME_LEN];
	volatile __u64 addr;
} addrs[] = {
	{"socket_file_ops", 0},
	{"bpf_map_fops_addr", 0},
	{"bpf_prog_fops_addr", 0},
	{"bpf_link_fops_addr", 0},
	{"eventpoll_fops_addr", 0},
	{"pipe_inode_info_addr", 0},
	{"tty_fops_addr", 0},
};

struct gadget_file {
  gadget_mntns_id mntns_id;
  char comm[TASK_COMM_LEN];
  __u32 ppid;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  __u32 fd;
  __u64 ino;
  __u64 f_op;
};

//GADGET_SNAPSHOTTER(ksyms, gadget_file, iter_ksym);
GADGET_SNAPSHOTTER(files, gadget_file, iter_file);

// iterators on ksym added in Linux 6.0

// For some reason, vmlinux.h only has bpf_iter__ksym in arm64.
#ifdef __TARGET_ARCH_x86
struct bpf_iter__ksym {
        union {
                struct bpf_iter_meta *meta;
        };
        union {
                struct kallsym_iter *ksym;
        };
};
#endif

/*
SEC("iter/ksym")
int iter_ksym(struct bpf_iter__ksym *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct kallsym_iter *iter = ctx->ksym;
	__u32 seq_num = ctx->meta->seq_num;
	unsigned long value;
	char type;
	int i;

	addrs[0].addr = 42;

	if (!iter)
		return 0;

#pragma unroll
	for (i = 0; i < ARRAY_SIZE(addrs); i++) {
		if (__builtin_memcmp(addrs[i].name, iter->name,
				     sizeof(addrs[i].name)) == 0)
			addrs[i].addr = iter->value;
	}
	return 0;
}
*/

// This iterates on all the open files (from all processes).
SEC("iter/task_file")
int iter_file(struct bpf_iter__task_file *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct file *file = ctx->file;
  struct task_struct *task = ctx->task;
  struct task_struct *parent;
  pid_t parent_pid;
  u64 mntns_id;

  struct gadget_file gadget_file = {};

  if (!file || !task)
    return 0;

  mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  __u64 f_op = (__u64)(file->f_op);

  parent = task->real_parent;
  if (!parent)
    parent_pid = -1;
  else
    parent_pid = parent->pid;

  gadget_file.mntns_id = mntns_id;
  __builtin_memcpy(gadget_file.comm, task->comm, TASK_COMM_LEN);
  gadget_file.ppid = parent_pid;
  gadget_file.pid = task->tgid;
  gadget_file.uid = task->cred->uid.val;
  gadget_file.gid = task->cred->gid.val;
  gadget_file.fd = ctx->fd;
  gadget_file.ino = file->f_inode->i_ino;
  gadget_file.f_op = f_op;

  bpf_seq_write(seq, &file, sizeof(file));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
