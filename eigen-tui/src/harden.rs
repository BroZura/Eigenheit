//! Process hardening. The ONLY module in EIGENHEIT that contains `unsafe`.
//! Each call is a plain libc syscall wrapper with no pointer juggling beyond
//! passing a stack struct by reference.
#![allow(unsafe_code)]

/// What the hardening pass achieved, shown honestly in the UI.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hardening {
    pub no_core: bool,
    pub nondumpable: bool,
    pub locked: bool,
}

pub fn apply() -> Hardening {
    let mut h = Hardening::default();
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid, initialised rlimit struct.
    h.no_core = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } == 0;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes integer arguments only.
        h.nondumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    }
    h.locked = try_lock_memory();
    h
}

/// Lock all memory only when the limit allows it entirely; a partial lock that
/// later makes allocations fail would be worse than an honest "swap: exposed".
fn try_lock_memory() -> bool {
    #[cfg(target_os = "linux")]
    {
        let inf = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: as above; failure is reported through the return value.
        let raised = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &inf) } == 0;
        let mut cur = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a valid stack struct.
        let ok = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut cur) } == 0;
        if raised || (ok && cur.rlim_cur == libc::RLIM_INFINITY) {
            // SAFETY: mlockall takes flags only.
            return unsafe {
                libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT)
            } == 0;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
