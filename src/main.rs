use crate::unistd::Gid;
use crate::unistd::Uid;
use crate::fs::File;
use crate::fs::Permissions;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd;
use nix::unistd::fork;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process;
use std::string::String;

mod ifreq;
mod tmp;

const NONE: Option<&'static [u8]> = None;

pub fn setdomainname<S: AsRef<OsStr>>(name: S) -> nix::Result<()> {
    let ptr = name.as_ref().as_bytes().as_ptr() as *const libc::c_char;
    let len = name.as_ref().len() as libc::size_t;

    let res = unsafe { libc::setdomainname(ptr, len) };
    nix::errno::Errno::result(res).map(drop)
}

fn bind_mount(source: &Path, dest: &Path) {
    let stat = fs::metadata(source)
        .unwrap_or_else(|err| panic!("cannot stat {}: {}", source.display(), err));
    if stat.file_type().is_dir() {
        fs::create_dir_all(&dest)
            .unwrap_or_else(|err| panic!("failed to create {}: {}", &dest.display(), err));
    } else {
        fs::create_dir_all(&dest.parent().expect("no parent"))
            .unwrap_or_else(|err| panic!("failed to create {}: {}", &dest.display(), err));
        fs::File::create(&dest)
            .unwrap_or_else(|err| panic!("failed to create {}: {}", &dest.display(), err));
    }
    if let Err(e) = mount(
        Some(source),
        dest,
        Some("none"),
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        NONE,
    ) {
        panic!(
            "failed to bind mount {} to {}: {}",
            source.display(),
            dest.display(),
            e
        );
    }
}

fn write_file(p: &Path, what: &str) {
    let mut buffer =
        File::create(&p).unwrap_or_else(|e| panic!("failed to create {}: {}", p.display(), e));
    buffer
        .write_all(what.as_bytes())
        .unwrap_or_else(|e| panic!("could not write {}: {}", p.display(), e));
}

fn create_loopback_interface() -> nix::Result<()> {
    let sock_fd = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let sock = unsafe { File::from_raw_fd(sock_fd) };

    let flags = ifreq::ifr_ifru {
        ifr_flags: (libc::IFF_UP | libc::IFF_LOOPBACK | libc::IFF_RUNNING) as libc::c_short,
    };
    let ifr = ifreq::ifreq {
        ifr_name: *b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ifr_ifru: flags,
    };

    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) };
    nix::errno::Errno::result(res).map(drop)
}

fn setup_fs(rootdir: &Path, shell: &str) {
    // mark all mounts as private
    mount(NONE, "/", NONE, MsFlags::MS_PRIVATE | MsFlags::MS_REC, NONE)
        .expect("failed to re-mount / as private");

    // bind paths to $chroot/
    let bind_paths = &[
        "nix",
        "dev/full",
        "dev/kvm",
        "dev/null",
        "dev/random",
        "dev/tty",
        "dev/urandom",
        "dev/zero",
        "dev/pts",
        "dev/ptmx",
    ];
    let host_root = PathBuf::from("/");
    for path in bind_paths {
        bind_mount(&host_root.join(path), &rootdir.join(path));
    }

    bind_mount(&PathBuf::from(shell), &rootdir.join("bin/sh"));

    let symlinks = [
        ("/proc/self/fd", "dev/fd"),
        ("/proc/self/fd/0", "dev/stdin"),
        ("/proc/self/fd/1", "dev/stdout"),
        ("/proc/self/fd/2", "dev/stderr"),
    ];

    for (original, link) in symlinks.iter() {
        let link = &rootdir.join(link);
        symlink(original, link).unwrap_or_else(|err| {
            panic!(
                "cannot create symlink from {} to {}: {}",
                original,
                link.display(),
                err
            )
        });
    }

    let shm = rootdir.join("dev/shm");
    unistd::mkdir(&shm, Mode::empty())
        .unwrap_or_else(|err| panic!("failed to create {}: {}", shm.display(), err));
    std::fs::set_permissions(&shm, Permissions::from_mode(0o1777)).expect("could not chmod /tmp");

    // we mount a tmpfs to our tmp dir that we can delete after performing the chroot
    mount(
        Some("none"),
        &shm,
        Some("tmpfs"),
        MsFlags::MS_NOATIME | MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Some("size=50%"),
    )
    .expect("failed to mount dev/shm");

    // create $chroot/tmp
    let tmp = rootdir.join("tmp");
    unistd::mkdir(&tmp, Mode::empty())
        .unwrap_or_else(|err| panic!("failed to create {}: {}", tmp.display(), err));
    std::fs::set_permissions(&tmp, Permissions::from_mode(0o1777)).expect("could not chmod /tmp");

    // create $chroot/tmp
    let etc = rootdir.join("etc");
    unistd::mkdir(&etc, Mode::S_IRWXU)
        .unwrap_or_else(|err| panic!("failed to create {}: {}", etc.display(), err));

    // Declare the build user's group so that programs get a consistent view of the system (e.g., "id -gn").
    write_file(
        &rootdir.join("etc/group"),
        "root:x:0:\nnixbld:!:100:\nnogroup:x:65534:\n",
    );

    // Create /etc/hosts with localhost entry.
    write_file(
        &rootdir.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n",
    );

    write_file(&rootdir.join("etc/passwd"),
               "root:x:0:0:Nix build user:/build:/noshell\nnixbld:x:1000:100:Nix build user:/build:/noshell\nnobody:x:65534:65534:Nobody:/:/noshell\n");
}

fn setup_uts_namespace() {
    // Set the hostname etc. to fixed values.
    unistd::sethostname("localhost").expect("cannot set hostname");
    // kernel default
    setdomainname("(none)").expect("cannot set domainname");
}

fn execute_child(rootdir: &Path, shell: &str, args: &[String]) {
    // Bind a new instance of procfs on /proc.
    let proc = rootdir.join("proc");
    let mode = Mode::S_IRUSR
        | Mode::S_IXUSR
        | Mode::S_IRGRP
        | Mode::S_IXGRP
        | Mode::S_IROTH
        | Mode::S_IXOTH;
    unistd::mkdir(&proc, mode)
        .unwrap_or_else(|err| panic!("failed to create {}: {}", proc.display(), err));
    mount(
        Some("proc"),
        &proc,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        NONE,
    )
    .expect("failed to mount /proc");

    // chroot /
    unistd::chroot(rootdir).unwrap_or_else(|err| panic!("chroot({}): {}", rootdir.display(), err));

    env::set_current_dir("/build").expect("cannot change directory to /build");

    // TODO seccomp!

    let err = process::Command::new(shell)
        .arg("-c")
        .arg("source /build/env-vars; exec \"$@\"")
        .arg("--")
        .env_clear()
        .args(args)
        .exec();

    eprintln!("Failed to execute shell {}: {}", shell, err);

    process::exit(1);
}

fn setup_usernamespace(uid: Uid, gid: Gid) {
    // fixes issue #1 where writing to /proc/self/gid_map fails
    // see user_namespaces(7) for more documentation
    if let Ok(mut file) = fs::File::create("/proc/self/setgroups") {
        let _ = file.write_all(b"deny");
    }
    fs::write(
        "/proc/self/uid_map",
        format!("{} {} 1", 1000, uid).as_bytes(),
    )
    .expect("failed to write uid_map");
    fs::write(
        "/proc/self/gid_map",
        format!("{} {} 1", 100, gid).as_bytes(),
    )
    .expect("failed to write gid_map");
}

fn run_chroot(builddir: &Path, shell: &str, args: &[String]) {
    let uid = unistd::getuid();
    let gid = unistd::getgid();

    let rootdir = tmp::tempdir().expect("Cannot create tempdir");

    // mount the build directory to $chroot/build
    let build_mount = rootdir.path().join("build");

    let status = process::Command::new("cp")
        .arg("-a")
        .arg(builddir)
        .arg(&build_mount)
        .status()
        .expect("failed to execute cp");
    if !status.success() {
        panic!(
            "Copying build directory with `cp -a {} {}` failed with: {}",
            builddir.display(),
            build_mount.display(),
            status
        )
    }

    unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWIPC,
    )
    .expect("unshare failed");

    setup_usernamespace(uid, gid);

    setup_uts_namespace();

    create_loopback_interface().expect("cannot setup loopback interface");

    setup_fs(rootdir.path(), shell);

    match unsafe { fork() } {
        Ok(unistd::ForkResult::Parent { child, .. }) => {
            if let WaitStatus::Exited(_, 0) =
                waitpid(child, None).expect("could not wait for child")
            {
                return;
            }
            // assuming that we already got an meaningful error message from the child
            process::exit(1);
        }
        Ok(unistd::ForkResult::Child) => {
            execute_child(rootdir.path(), shell, args);
        }
        Err(e) => {
            panic!("fork failed: {}", e);
        }
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <builddir>\n", args[0]);
        process::exit(1);
    }

    let builddir = fs::canonicalize(&args[1])
        .unwrap_or_else(|err| panic!("failed to resolve build directory {}: {}", &args[1], err));

    let envvars = builddir.join("env-vars");
    if !envvars.exists() {
        eprintln!(
            "{} does not contain env-vars, not a valid nix build directory.",
            envvars.display()
        );
        process::exit(1);
    }
    let env_file =
        File::open(&envvars).unwrap_or_else(|e| panic!("cannot open {}: {}", envvars.display(), e));
    let prefix = "declare -x SHELL=\"";
    let shell_var = BufReader::new(env_file).lines().find_map(|line| {
        if let Ok(line) = line {
            if line.starts_with(prefix) {
                return Some(line);
            }
        }
        None
    });

    let shell = match shell_var {
        Some(s) => String::from(&s[prefix.len()..(s.len() - 1)]),
        None => panic!("did not find build shell in {}", envvars.display()),
    };

    let mut cmd = &args[2..];
    let fallback_cmd = &["/bin/sh".to_string()];
    if cmd.is_empty() {
        cmd = fallback_cmd;
    }
    run_chroot(&builddir, &shell, cmd);
}
