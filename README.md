# Linux Rootkit

A simple Linux kernel rootkit written for fun, not evil.

## Functionality

The rootkit can do the following:

- Grant root privileges to a userland process
- Hide process by PID
- Unhide a previously hidden process by PID
- Hide files or directories by their name
- Unhide previously hidden files or directories
- Hide itself
- Unhide itself
- Protect against being unloaded by the user
- Disable the unload protection

## Supported Platforms

The rootkit was tested to work on Linux kernels 2.6.32-38 and 4.4.0-22 as provided by Ubuntu in Ubuntu 10.04.4 LTS and Ubuntu 16.04 LTS respectively, but it should be very easy to port to kernels in-between, as well as newer ones.

There is some architecture-specific code in the rootkit which is implemented only for x86 and x86-64 architectures.
That's the code for finding the system call table, disabling write-protected memory and one of the two function hooking methods.
It should be very easy to port to a new architecture, and some of this code is not strictly necessary for the rootkit to function, e.g. the non-portable hooking method could be stripped away, though you must be a very boring person if you are willing to miss on the fun of function hooking that overwrites machine code of the target kernel function such that it calls our hook function instead.

The rootkit was tested only with 1 CPU core, so it may or may not function correctly on a multi-core system.
It likely won't run very well on a multi-core system as the rootkit was written expecting there to be only 1 thread executing anything at any given time, so it lacks atomic writes/reads and mutexes around list data structures.

## Build

### Setting Up Environment

Warm up your VM of choice.

Grab and install the desired Ubuntu image:

| Kernel / arch |         x86         |        x86-64        |
|:-------------:|:-------------------:|:--------------------:|
|     2.6.32    | Ubuntu 10.04.4 i386 (694M) [[torrent]](http://old-releases.ubuntu.com/releases/10.04.0/ubuntu-10.04.4-server-i386.iso.torrent) [[iso]](http://old-releases.ubuntu.com/releases/10.04.0/ubuntu-10.04.4-server-i386.iso) | Ubuntu 10.04.4 amd64 (681M) [[torrent]](http://old-releases.ubuntu.com/releases/10.04.0/ubuntu-10.04.4-server-amd64.iso.torrent) [[iso]](http://old-releases.ubuntu.com/releases/10.04.0/ubuntu-10.04.4-server-amd64.iso) |
|     4.4.0     | Ubuntu 16.04 i386 (647M) [[torrent]](http://old-releases.ubuntu.com/releases/16.04.0/ubuntu-16.04-server-i386.iso.torrent) [[iso]](http://old-releases.ubuntu.com/releases/16.04.0/ubuntu-16.04-server-i386.iso) |  Ubuntu 16.04 amd64 (655M) [[torrent]](http://old-releases.ubuntu.com/releases/16.04.0/ubuntu-16.04-server-amd64.iso.torrent) [[iso]](http://old-releases.ubuntu.com/releases/16.04.0/ubuntu-16.04-server-amd64.iso) |

For Ubuntu 10.04, patch the package repository address:

```sh
sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
```

Install a compiler, Linux headers and all other things required for us to build the rootkit:

```sh
apt-get update
apt-get install build-essential
```

Make sure not to call `apt-get upgrade`, as it would update the kernel, when the rootkit was tested only on the pre-installed kernel version.

### Actual Building

```sh
make
```

## Use

Load rootkit:

```sh
insmod rootkit.ko
```

Use rootkit:

```sh
$ ./client --help
Usage: ./client [OPTION]...

Options:
  --root-shell            Grants you root shell access.
  --hide-pid=PID          Hides the specified PID.
  --unhide-pid=PID        Unhides the specified PID.
  --hide-file=FILENAME    Hides the specified FILENAME globally.
                          Must be a filename without any path.
  --unhide-file=FILENAME  Unhides the specified FILENAME.
  --hide                  Hides the rootkit LKM.
  --unhide                Unhides the rootkit LKM.
  --help                  Print this help message.
  --protect               Protects the rootkit from rmmod.
  --unprotect             Disables the rmmod protection.
```

Unload rootkit:

```sh
./client --unhide
./client --unprotect
rmmod rootkit.ko
```

## YOU ARE OUT OF YOUR MIND TO PUBLICY RELEASE SUCH MALICIOUS CODE ONLINE, YOU ARE LITERALLY ARMING SCRIPT KIDDIES WITH NUKES!!!1
Not really, there are many articles online on how to write a Linux rootkit with the full source code provided, not to mention the countless GitHub repositories.

## References
The following materials were used in writing this rootkit:

- [Linux kernel code](http://lxr.free-electrons.com)
- [Linux kernel documentation](https://www.kernel.org/doc/)
- [Linux Loadable Kernel Module HOWTO](http://www.tldp.org/HOWTO/html_single/Module-HOWTO/)
- [WRITING A SIMPLE ROOTKIT FOR LINUX](https://web.archive.org/web/20180609141026/https://w3.cs.jmu.edu/kirkpams/550-f12/papers/linux_rootkit.pdf)
- [Modern Linux Rootkits 101](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
- [Writing Modern Linux Rootkits 201 - VFS](http://turbochaos.blogspot.com/2013/10/writing-linux-rootkits-201-23.html)
- [Linux Kernel Module example. Rickroll prank.](https://web.archive.org/web/20170218150045/http://maitesin.github.io/Module_prank/)

## License
This project is licensed under [GPLv2](LICENSE).
