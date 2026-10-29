# cannc — experimental project overview

This repository contains the project-authored Python CLI and a draft Homebrew integration for an unofficial experimental Ascend C build workflow on Apple Silicon. It is shared as source code while applicable terms and possible permission from Huawei for third-party components are being clarified. It is not a complete or production-ready product, and it is not affiliated with or endorsed by Huawei.

## Architecture

The CLI runs the original Linux AArch64 BiSheng compiler through elfuse, a Linux userspace compatibility runtime for macOS using Apple Hypervisor.framework. It prepares a fixed execution environment and target sysroot, invokes the compiler and linker, checks output structure, and records build and recovery metadata. Its output is intended for Linux AArch64 systems with Ascend devices.

The Python source is the project's own code, licensed under Apache License 2.0. BiSheng, CANN runtime and headers, Linux target snapshots, elfuse binaries, bundled installers, compiled ELF files, hardware results and vendor example source code are not included in this repository. Third-party software remains subject to its own terms. `config/input-lock.json` is a local experiment's metadata; it is not proof of upstream origin, redistribution rights, or broad compatibility.

## Scope and status

The present implementation supports only an experimental pinned profile. The Homebrew formula is a draft: its future download URL is not live and the required third-party components are not included here. This repository alone cannot build a working complete environment; a licensed set of exact dependencies would be required. No GitHub release has been published.

To inspect the CLI help from this source checkout with Python 3.12 or newer:

```sh
python3 bin/cannc --help
```

The files under `homebrew/` describe the prototype packaging integration. The proposed bundled release and its licensing are under discussion; no claim is made that any third-party component can be redistributed.
