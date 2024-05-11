# snapshot-file

snapshot-file is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It gather information about open files.

## How to use

```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run ghcr.io/alban/snapshot-file:latest
```

## Requirements

- ig v0.26.0 (TBD)
- Linux v6.0
  - [ksym iterators](https://github.com/torvalds/linux/commit/647cafa223490)

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
