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

const volatile __u64 socket_file_ops_addr = 0;
const volatile __u64 bpf_map_fops_addr = 0;
const volatile __u64 bpf_prog_fops_addr = 0;
const volatile __u64 bpf_link_fops_addr = 0;
const volatile __u64 eventpoll_fops_addr = 0;
const volatile __u64 pipefifo_fops_addr = 0;
const volatile __u64 tty_fops_addr = 0;

GADGET_PARAM(socket_file_ops_addr);
GADGET_PARAM(bpf_map_fops_addr);
GADGET_PARAM(bpf_prog_fops_addr);
GADGET_PARAM(bpf_link_fops_addr);
GADGET_PARAM(eventpoll_fops_addr);
GADGET_PARAM(pipefifo_fops_addr);
GADGET_PARAM(tty_fops_addr);

enum file_type {
  unknown,
  socket,
  bpfmap,
  bpfprog,
  bpflink,
  eventpoll,
  pipe,
  tty,
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
  enum file_type file_type;
};

GADGET_SNAPSHOTTER(files, gadget_file, iter_file);

static __always_inline enum file_type f_op_to_file_type(__u64 f_op) {
  if (f_op == 0)
    return unknown;

  if (f_op == socket_file_ops_addr)
    return socket;
  if (f_op == bpf_map_fops_addr)
    return bpfmap;
  if (f_op == bpf_prog_fops_addr)
    return bpfprog;
  if (f_op == bpf_link_fops_addr)
    return bpflink;
  if (f_op == eventpoll_fops_addr)
    return eventpoll;
  if (f_op == pipefifo_fops_addr)
    return pipe;
  if (f_op == tty_fops_addr)
    return tty;

  return unknown;
}

// This iterates on all the open files (from all processes).
SEC("iter/task_file")
int iter_file(struct bpf_iter__task_file *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct file *file = ctx->file;
  struct task_struct *task = ctx->task;
  struct task_struct *parent;
  pid_t parent_pid;
  u64 mntns_id;
  long ret;

  struct gadget_file gadget_file = {};

  if (!file || !task)
    return 0;

  mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  gadget_file.file_type = f_op_to_file_type((__u64)(file->f_op));


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

  bpf_seq_write(seq, &gadget_file, sizeof(gadget_file));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
