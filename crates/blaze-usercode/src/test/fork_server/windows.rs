
// blaze's fork server on Windows, which has no fork: the harness text of
// `blaze_usercode::test::fork_server`, after `fork_server.rs` and before the `exec` module. The
// protocol is `wire.rs`'s, unchanged; blaze's queue sees a server whose fork costs nothing (it
// says 0 in its hello), so it asks for no replicas and sends it as many tests at once as it has
// cores.
//
// A test runs in a process of its own: the binary again, started with `SOCKET` set to [`CHILD`]
// before the test is asked for (warm), in a job of its own that kills every process it starts
// when the job closes. A warm process waits on its standard input for the index of the test it
// runs (four bytes), runs it as libtest would (`one::run`), with standard output and error on one
// pipe the server reads, and exits with the test's code. So a test starts with one write to a
// pipe, not a process start (5 to 15 ms on Windows), and the server starts the next warm process
// while the test runs. A kill (`Frame::Kill`) ends the test's job: the test and every process it
// started. A test's own end ends its job too: a process it left behind holding its output would
// keep the output from ending.
//
// The server reads blaze's frames on its main thread; each running test has a thread that reads
// its output and one that waits for its process, which then answers `Frame::Ended` under the
// socket's lock. Nothing the server does is recorded in the sandbox's record: Windows' sandbox
// keeps no record of what one test reads, and blaze takes every result of this server as not
// traced (`queue`'s `lines`).
#[cfg(windows)]
mod windows {
    use super::std;
    #[allow(unused_imports)]
    use self::std::prelude::rust_2021::*;
    #[allow(unused_imports)]
    use self::std::{eprintln, format, vec};
    use super::super::test;
    use super::{EndView, ExecView, Frames, LONGEST_OUTPUT, SOCKET, UNRECORDED, VERSION, View, encode_ended, encode_hello};
    use self::std::io::{Read, Write};
    use self::std::sync::{Arc, Condvar, Mutex};

    /// The value of `SOCKET` a warm process is started with: it runs one test and exits.
    pub const CHILD: &str = "\u{1}blaze-test-child";

    /// The warm processes kept ready, at most: as many as the machine's threads, up to this.
    const WARM_MOST: usize = 8;

    /// The exit code of a test whose job a kill ended.
    const KILLED: u32 = 0xC000_013A;

    type Handle = *mut ::core::ffi::c_void;
    type Bool = i32;
    type Socket = usize;

    const INVALID_SOCKET: Socket = !0;
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const HANDLE_FLAG_INHERIT: u32 = 1;
    const STARTF_USESTDHANDLES: u32 = 0x100;
    const CREATE_SUSPENDED: u32 = 0x4;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x8_0000;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x2_0002;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x400;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut ::core::ffi::c_void,
        inherit: Bool,
    }

    #[repr(C)]
    struct StartupInfo {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_chars: u32,
        y_chars: u32,
        fill: u32,
        flags: u32,
        show: u16,
        reserved2_len: u16,
        reserved2: *mut u8,
        input: Handle,
        output: Handle,
        error: Handle,
    }

    #[repr(C)]
    struct StartupInfoEx {
        info: StartupInfo,
        attributes: *mut ::core::ffi::c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: u32,
        thread_id: u32,
    }

    #[repr(C)]
    struct BasicLimits {
        per_process_user_time: i64,
        per_job_user_time: i64,
        flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        active_processes: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }

    #[repr(C)]
    struct SockaddrUn {
        family: u16,
        path: [u8; 108],
    }

    #[repr(C)]
    struct WsaData {
        // Past what any version of `WSADATA` holds on 64-bit Windows (408 bytes).
        bytes: [u8; 512],
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    unsafe extern "system" {
        fn CreatePipe(read: *mut Handle, write: *mut Handle, attributes: *const SecurityAttributes, size: u32) -> Bool;
        fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> Bool;
        fn CreateProcessW(
            application: *const u16,
            command: *mut u16,
            process_attributes: *const ::core::ffi::c_void,
            thread_attributes: *const ::core::ffi::c_void,
            inherit: Bool,
            flags: u32,
            environment: *const ::core::ffi::c_void,
            directory: *const u16,
            startup: *const StartupInfo,
            information: *mut ProcessInformation,
        ) -> Bool;
        fn InitializeProcThreadAttributeList(list: *mut ::core::ffi::c_void, count: u32, flags: u32, size: *mut usize) -> Bool;
        fn UpdateProcThreadAttribute(
            list: *mut ::core::ffi::c_void,
            flags: u32,
            attribute: usize,
            value: *const ::core::ffi::c_void,
            size: usize,
            previous: *mut ::core::ffi::c_void,
            returned: *mut usize,
        ) -> Bool;
        fn DeleteProcThreadAttributeList(list: *mut ::core::ffi::c_void);
        fn CreateJobObjectW(attributes: *const ::core::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, information: *const ::core::ffi::c_void, size: u32) -> Bool;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
        fn TerminateJobObject(job: Handle, code: u32) -> Bool;
        fn ResumeThread(thread: Handle) -> u32;
        fn CloseHandle(handle: Handle) -> Bool;
        fn ReadFile(file: Handle, buffer: *mut u8, size: u32, read: *mut u32, overlapped: *mut ::core::ffi::c_void) -> Bool;
        fn WriteFile(file: Handle, buffer: *const u8, size: u32, written: *mut u32, overlapped: *mut ::core::ffi::c_void) -> Bool;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(process: Handle, code: *mut u32) -> Bool;
        fn GetModuleFileNameW(module: Handle, name: *mut u16, size: u32) -> u32;
    }

    #[link(name = "ws2_32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    unsafe extern "system" {
        fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
        fn WSAGetLastError() -> i32;
        fn socket(family: i32, kind: i32, protocol: i32) -> Socket;
        fn connect(socket: Socket, address: *const SockaddrUn, length: i32) -> i32;
        fn send(socket: Socket, buffer: *const u8, length: i32, flags: i32) -> i32;
        fn recv(socket: Socket, buffer: *mut u8, length: i32, flags: i32) -> i32;
        fn closesocket(socket: Socket) -> i32;
    }

    /// A handle this process owns, closed once at its drop.
    struct Owned(Handle);

    // SAFETY: a kernel handle is a number any thread may use; each is closed once, by its drop.
    unsafe impl Send for Owned {}
    // SAFETY: as above; the calls made through a shared one (a wait, a termination) are safe
    // from any thread at once.
    unsafe impl Sync for Owned {}

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: a handle this owner opened and nothing else closes.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn last_error(what: &str) -> String {
        format!("{}: {}", what, std::io::Error::last_os_error()) // alloc: error path
    }

    /// The connection to blaze: read by the main thread alone, written by any thread under
    /// [`Shared::sending`] (Winsock sends and receives on one socket from two threads at once).
    struct Conn(Socket);

    impl Conn {
        fn send_all(&self, mut bytes: &[u8]) -> Result<(), String> {
            while !bytes.is_empty() {
                let chunk = bytes.len().min(1 << 30) as i32;
                // SAFETY: an open socket and `chunk` bytes of a live buffer to send.
                let sent = unsafe { send(self.0, bytes.as_ptr(), chunk, 0) };
                if sent <= 0 {
                    // SAFETY: no argument; reads this thread's last socket error.
                    return Err(format!("writing to the socket: error {}", unsafe { WSAGetLastError() })); // alloc: error path
                }
                bytes = &bytes[sent as usize..];
            }
            Ok(())
        }

        /// Up to `buffer`'s bytes; 0 when blaze closed its end.
        fn recv(&self, buffer: &mut [u8]) -> Result<usize, String> {
            // SAFETY: an open socket and a live buffer of its length to fill.
            let got = unsafe { recv(self.0, buffer.as_mut_ptr(), buffer.len().min(1 << 30) as i32, 0) };
            if got < 0 {
                // SAFETY: as above.
                return Err(format!("reading the socket: error {}", unsafe { WSAGetLastError() })); // alloc: error path
            }
            Ok(got as usize)
        }
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            // SAFETY: a socket this owner opened and nothing else closes.
            unsafe { closesocket(self.0) };
        }
    }

    fn connect_to(path: &std::ffi::OsStr) -> Result<Conn, String> {
        let text = path.to_str().ok_or_else(|| format!("the socket's path {:?} is not UTF-8", path))?; // alloc: error path
        let mut address = SockaddrUn { family: AF_UNIX as u16, path: [0; 108] };
        if text.len() >= address.path.len() {
            return Err(format!("the socket's path {} is longer than a Unix socket's ({} bytes)", text, address.path.len() - 1)); // alloc: error path
        }
        address.path[..text.len()].copy_from_slice(text.as_bytes());
        let mut data = WsaData { bytes: [0; 512] };
        // SAFETY: `data` is writable and larger than any `WSADATA`.
        if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
            return Err(last_error("WSAStartup"));
        }
        // blaze listens as it starts the binary; the listen may be made a moment after.
        let mut tries = 0;
        loop {
            // SAFETY: integers only.
            let made = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
            if made == INVALID_SOCKET {
                // SAFETY: no argument.
                return Err(format!("a Unix socket: error {}", unsafe { WSAGetLastError() })); // alloc: error path
            }
            let conn = Conn(made);
            // SAFETY: an open socket and an address of the size given.
            let done = unsafe { connect(conn.0, &address, ::core::mem::size_of::<SockaddrUn>() as i32) };
            if done == 0 {
                return Ok(conn);
            }
            // SAFETY: no argument.
            let error = unsafe { WSAGetLastError() };
            drop(conn);
            if tries >= 400 {
                return Err(format!("connecting to {}: error {}", text, error)); // alloc: error path
            }
            tries += 1;
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// A process started ahead of its test, waiting for the test's index on its input.
    struct Warm {
        process: Owned,
        job: Owned,
        /// Where the test's index is written.
        input: Owned,
        /// Its standard output and error.
        output: Owned,
    }

    /// One pipe, both ends; the child's end inheritable, the server's not.
    fn pipe(child_reads: bool) -> Result<(Owned, Owned), String> {
        let attributes = SecurityAttributes { length: ::core::mem::size_of::<SecurityAttributes>() as u32, descriptor: ::core::ptr::null_mut(), inherit: 1 };
        let (mut read, mut write): (Handle, Handle) = (::core::ptr::null_mut(), ::core::ptr::null_mut());
        // SAFETY: two handles to write and attributes of the size they say.
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(last_error("a pipe for a test"));
        }
        let (read, write) = (Owned(read), Owned(write));
        let ours = if child_reads { &write } else { &read };
        // SAFETY: a handle just made; only its inheritance changes.
        if unsafe { SetHandleInformation(ours.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(last_error("a pipe for a test"));
        }
        Ok((read, write))
    }

    /// This binary's path, as a quoted command line ending in a NUL.
    fn own_command() -> Result<(Vec<u16>, Vec<u16>), String> {
        let mut name = vec![0u16; 32768];
        // SAFETY: a buffer of the length given; the null module is this executable.
        let len = unsafe { GetModuleFileNameW(::core::ptr::null_mut(), name.as_mut_ptr(), name.len() as u32) } as usize;
        if len == 0 || len >= name.len() {
            return Err(last_error("this test binary's path"));
        }
        name.truncate(len);
        let mut line = Vec::with_capacity(len + 3);
        line.push(b'"' as u16);
        line.extend_from_slice(&name);
        line.push(b'"' as u16);
        line.push(0);
        name.push(0);
        Ok((name, line))
    }

    /// A job that kills what is in it when it closes, and keeps a crash from asking anyone.
    fn job() -> Result<Owned, String> {
        // SAFETY: no attributes, no name.
        let job = unsafe { CreateJobObjectW(::core::ptr::null(), ::core::ptr::null()) };
        if job.is_null() {
            return Err(last_error("a job for a test"));
        }
        let job = Owned(job);
        // SAFETY: all zeros is a limit of nothing for these plain integers.
        let mut limits: ExtendedLimits = unsafe { ::core::mem::zeroed() };
        limits.basic.flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        // SAFETY: an open job and information of the class named, of its size.
        let set = unsafe {
            SetInformationJobObject(job.0, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS, (&limits as *const ExtendedLimits).cast(), ::core::mem::size_of::<ExtendedLimits>() as u32)
        };
        if set == 0 {
            return Err(last_error("a job's limits"));
        }
        Ok(job)
    }

    /// A warm process: this binary with `SOCKET` set to [`CHILD`] (the server's own
    /// environment, which it set so), suspended, put in a job of its own, then let go to wait for
    /// its test. It inherits its two pipe ends and nothing else.
    fn start_warm(program: &[u16], line: &[u16]) -> Result<Warm, String> {
        let (input_read, input_write) = pipe(true)?;
        let (output_read, output_write) = pipe(false)?;
        let inherited: [Handle; 2] = [input_read.0, output_write.0];
        let mut size = 0usize;
        // SAFETY: a null list asks only for the size of one of one attribute.
        unsafe { InitializeProcThreadAttributeList(::core::ptr::null_mut(), 1, 0, &mut size) };
        let mut list = vec![0u64; size.div_ceil(8)];
        let at = list.as_mut_ptr().cast::<::core::ffi::c_void>();
        // SAFETY: a buffer of at least `size` bytes, aligned for the list.
        if unsafe { InitializeProcThreadAttributeList(at, 1, 0, &mut size) } == 0 {
            return Err(last_error("a test process's attributes"));
        }
        // SAFETY: the list made above; the handles live past the process's start, which reads
        // them.
        let updated = unsafe {
            UpdateProcThreadAttribute(at, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.as_ptr().cast(), ::core::mem::size_of_val(&inherited), ::core::ptr::null_mut(), ::core::ptr::null_mut())
        };
        if updated == 0 {
            // SAFETY: the list initialized above, deleted once.
            unsafe { DeleteProcThreadAttributeList(at) };
            return Err(last_error("a test process's handles"));
        }
        // SAFETY: all zeros is a valid start of the plain fields it has.
        let mut startup: StartupInfoEx = unsafe { ::core::mem::zeroed() };
        startup.info.cb = ::core::mem::size_of::<StartupInfoEx>() as u32;
        startup.info.flags = STARTF_USESTDHANDLES;
        startup.info.input = input_read.0;
        startup.info.output = output_write.0;
        startup.info.error = output_write.0;
        startup.attributes = at;
        let mut command = line.to_vec();
        // SAFETY: all zeros is a valid start of what the call writes.
        let mut information: ProcessInformation = unsafe { ::core::mem::zeroed() };
        // SAFETY: NUL-ended program and line (the line writable, as the call asks); the startup
        // information and its attribute list live across the call; null environment and
        // directory are the server's.
        let made = unsafe {
            CreateProcessW(
                program.as_ptr(),
                command.as_mut_ptr(),
                ::core::ptr::null(),
                ::core::ptr::null(),
                1,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                ::core::ptr::null(),
                ::core::ptr::null(),
                &startup.info,
                &mut information,
            )
        };
        // SAFETY: the list initialized above, deleted once, after the call that read it.
        unsafe { DeleteProcThreadAttributeList(at) };
        if made == 0 {
            return Err(last_error("starting a test process"));
        }
        let (process, thread) = (Owned(information.process), Owned(information.thread));
        let job = job()?;
        // SAFETY: an open job and the process just made, suspended.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let why = last_error("putting a test process in its job");
            // SAFETY: the process just made, which runs nothing yet.
            unsafe { TerminateJobObject(job.0, KILLED) };
            return Err(why);
        }
        // SAFETY: its first thread, suspended once at its making.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let why = last_error("letting a test process go");
            // SAFETY: an open job.
            unsafe { TerminateJobObject(job.0, KILLED) };
            return Err(why);
        }
        // The child's ends are the child's now: closed here, so its output ends when it does.
        drop((input_read, output_write));
        Ok(Warm { process, job, input: input_write, output: output_read })
    }

    /// What every thread of the server shares.
    struct Shared {
        conn: Conn,
        /// Held across one answer's send, so two answers never interleave.
        sending: Mutex<()>,
        /// The jobs of the tests running, by their ids.
        running: Mutex<Vec<(u64, Arc<Owned>)>>,
        /// How many tests run; the main thread waits on it to end at a quit.
        ended: Condvar,
    }

    /// The warm processes, kept filled by a thread of their own.
    struct Pool {
        warm: Mutex<(Vec<Warm>, bool)>,
        wanted: Condvar,
    }

    pub fn serve(tests: &'static [&'static test::TestDescAndFn], socket: &std::ffi::OsStr) -> Result<(), String> {
        // Taken out before any test runs, so a test that runs its own binary gets libtest; set
        // to `CHILD` for the warm processes, which inherit this environment.
        // SAFETY: the harness's `main` calls this before it starts any thread, so no other
        // thread reads the environment as it changes.
        unsafe { std::env::set_var(SOCKET, CHILD) };
        let (program, line) = own_command()?;
        let conn = connect_to(socket)?;
        let mut out: Vec<u8> = Vec::new(); // alloc: setup, once per server
        // A test is handed to a process already started: no fork, nothing to measure.
        encode_hello(&mut out, VERSION, std::process::id(), 0, tests.iter().map(|it| it.desc.name.as_slice()));
        conn.send_all(&out)?;
        let shared = Arc::new(Shared { conn, sending: Mutex::new(()), running: Mutex::new(Vec::new()), ended: Condvar::new() });
        let most = std::thread::available_parallelism().map_or(1, |it| it.get()).min(WARM_MOST);
        let pool = Arc::new(Pool { warm: Mutex::new((Vec::new(), false)), wanted: Condvar::new() });
        let filler = {
            let pool = Arc::clone(&pool);
            let (program, line) = (program.clone(), line.clone());
            std::thread::Builder::new()
                .name("blaze-test-warm".to_owned())
                .spawn(move || fill(&pool, most, &program, &line))
                .map_err(|error| format!("the thread that starts test processes: {}", error))? // alloc: error path
        };
        let ended = serve_frames(tests, &shared, &pool, &program, &line);
        // Whatever ended the loop, the warm processes go: their input closes (they read no
        // index and exit) and their jobs close.
        {
            let mut warm = pool.warm.lock().unwrap_or_else(|it| it.into_inner());
            warm.1 = true;
            warm.0.clear();
        }
        pool.wanted.notify_all();
        let _ = filler.join();
        ended
    }

    /// Keeps `most` warm processes ready until the pool is closed.
    fn fill(pool: &Pool, most: usize, program: &[u16], line: &[u16]) {
        loop {
            {
                let mut warm = pool.warm.lock().unwrap_or_else(|it| it.into_inner());
                while !warm.1 && warm.0.len() >= most {
                    warm = pool.wanted.wait(warm).unwrap_or_else(|it| it.into_inner());
                }
                if warm.1 {
                    return;
                }
            }
            // Started outside the lock: a test taken meanwhile does not wait for it.
            match start_warm(program, line) {
                Ok(made) => {
                    let mut warm = pool.warm.lock().unwrap_or_else(|it| it.into_inner());
                    if warm.1 {
                        return;
                    }
                    warm.0.push(made);
                }
                Err(why) => {
                    // The main thread starts its own when none is warm, and says why there.
                    eprintln!("blaze's fork server: a warm test process: {}", why);
                    return;
                }
            }
        }
    }

    fn serve_frames(
        tests: &'static [&'static test::TestDescAndFn],
        shared: &Arc<Shared>,
        pool: &Pool,
        program: &[u16],
        line: &[u16],
    ) -> Result<(), String> {
        let mut frames = Frames::new();
        let mut buffer = vec![0u8; 1 << 16]; // alloc: setup, once per server
        let mut out: Vec<u8> = Vec::new(); // alloc: setup, once per server
        let mut first = true;
        loop {
            // A read holds no lock: a test's answer is sent beside it.
            let got = match shared.conn.recv(&mut buffer) {
                Ok(0) => {
                    // blaze is gone: nothing will read what the tests say.
                    kill_all(shared);
                    return Ok(());
                }
                Ok(n) => n,
                Err(why) => {
                    kill_all(shared);
                    return Err(why);
                }
            };
            frames.push(&buffer[..got]);
            loop {
                let frame = match frames.pop_view() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(why) => {
                        kill_all(shared);
                        return Err(why);
                    }
                };
                let was_first = ::core::mem::replace(&mut first, false);
                match frame {
                    // Said a fork costs nothing, blaze asks for none; one more is a server of
                    // its own it would wait for, which this process does not make.
                    View::Replicate { count } => {
                        if !was_first || count > 0 {
                            kill_all(shared);
                            return Err(format!("blaze asked for {} replicas of a server that said its fork costs nothing", count)); // alloc: error path
                        }
                    }
                    View::Run { id, index } => {
                        if let Err(why) = start(tests, shared, pool, program, line, id, index) {
                            out.clear();
                            encode_ended(&mut out, id, EndView::NotStarted(&why), &[], ExecView::Not(UNRECORDED));
                            let _sending = shared.sending.lock().unwrap_or_else(|it| it.into_inner());
                            shared.conn.send_all(&out)?;
                        }
                    }
                    View::Kill { id } => {
                        let running = shared.running.lock().unwrap_or_else(|it| it.into_inner());
                        if let Some((_, job)) = running.iter().find(|it| it.0 == id) {
                            // SAFETY: an open job; ending it twice is nothing.
                            unsafe { TerminateJobObject(job.0, KILLED) };
                        }
                    }
                    View::Quit => {
                        let mut running = shared.running.lock().unwrap_or_else(|it| it.into_inner());
                        while !running.is_empty() {
                            running = shared.ended.wait(running).unwrap_or_else(|it| it.into_inner());
                        }
                        return Ok(());
                    }
                    other => {
                        kill_all(shared);
                        return Err(format!("blaze sent {:?}, which only a server sends", other)); // alloc: error path
                    }
                }
            }
        }
    }

    fn kill_all(shared: &Shared) {
        let running = shared.running.lock().unwrap_or_else(|it| it.into_inner());
        for (_, job) in running.iter() {
            // SAFETY: an open job.
            unsafe { TerminateJobObject(job.0, KILLED) };
        }
    }

    /// Hands test `index` to a warm process (one started now when none is), under `id`.
    fn start(
        tests: &'static [&'static test::TestDescAndFn],
        shared: &Arc<Shared>,
        pool: &Pool,
        program: &[u16],
        line: &[u16],
        id: u64,
        index: u32,
    ) -> Result<(), String> {
        if index as usize >= tests.len() {
            return Err(format!("the binary has {} tests, and no test {}", tests.len(), index)); // alloc: error path
        }
        let taken = {
            let mut warm = pool.warm.lock().unwrap_or_else(|it| it.into_inner());
            let taken = warm.0.pop();
            pool.wanted.notify_one();
            taken
        };
        let warm = match taken {
            Some(warm) => warm,
            None => start_warm(program, line)?,
        };
        let bytes = index.to_le_bytes();
        let mut written = 0u32;
        // SAFETY: the pipe's write end, four bytes of a live buffer.
        let wrote = unsafe { WriteFile(warm.input.0, bytes.as_ptr(), 4, &mut written, ::core::ptr::null_mut()) };
        if wrote == 0 || written != 4 {
            let why = last_error("handing a test to its process");
            // SAFETY: an open job.
            unsafe { TerminateJobObject(warm.job.0, KILLED) };
            return Err(why);
        }
        let Warm { process, job, input, output } = warm;
        drop(input);
        let job = Arc::new(job);
        shared.running.lock().unwrap_or_else(|it| it.into_inner()).push((id, Arc::clone(&job)));
        let shared = Arc::clone(shared);
        std::thread::Builder::new()
            .name("blaze-test-wait".to_owned())
            .spawn(move || ended(&shared, id, process, job, output))
            .map(|_| ())
            .map_err(|error| format!("the thread that waits for a test: {}", error)) // alloc: error path
    }

    /// Reads the test's output on a thread of its own, waits for its process, ends its job (and
    /// with it whatever it left running, so its output ends), and answers how it ended.
    fn ended(shared: &Shared, id: u64, process: Owned, job: Arc<Owned>, output: Owned) {
        let reader = std::thread::Builder::new().name("blaze-test-output".to_owned()).spawn(move || read_output(output));
        // SAFETY: an open process handle.
        unsafe { WaitForSingleObject(process.0, INFINITE) };
        let mut code = 0u32;
        // SAFETY: an open process handle that has ended, and a code to write.
        let read = unsafe { GetExitCodeProcess(process.0, &mut code) };
        // SAFETY: an open job; what the test left behind goes with it.
        unsafe { TerminateJobObject(job.0, KILLED) };
        let (bytes, cut) = match reader {
            Ok(reader) => reader.join().unwrap_or_else(|_| (Vec::new(), false)),
            Err(_) => (Vec::new(), false),
        };
        let mut bytes = bytes;
        if cut {
            let _ = write!(bytes, "\n[blaze: the output was cut at {} bytes]\n", LONGEST_OUTPUT);
        }
        let mut out: Vec<u8> = Vec::new(); // alloc: a test's answer
        let end = match read {
            0 => EndView::NotStarted("its exit code could not be read"),
            _ => EndView::Exited(code as i32),
        };
        encode_ended(&mut out, id, end, &bytes, ExecView::Not(UNRECORDED));
        let sent = {
            let _sending = shared.sending.lock().unwrap_or_else(|it| it.into_inner());
            shared.conn.send_all(&out)
        };
        if let Err(why) = sent {
            eprintln!("blaze's fork server: {}", why);
        }
        let mut running = shared.running.lock().unwrap_or_else(|it| it.into_inner());
        running.retain(|it| it.0 != id);
        shared.ended.notify_all();
    }

    /// A test's output to its end, at most [`LONGEST_OUTPUT`] bytes, and whether it was cut.
    fn read_output(output: Owned) -> (Vec<u8>, bool) {
        let mut bytes: Vec<u8> = Vec::new(); // alloc: a test's output
        let mut cut = false;
        let mut buffer = [0u8; 1 << 14];
        loop {
            let mut got = 0u32;
            // SAFETY: the pipe's read end and a live buffer of the size given.
            let ok = unsafe { ReadFile(output.0, buffer.as_mut_ptr(), buffer.len() as u32, &mut got, ::core::ptr::null_mut()) };
            if ok == 0 || got == 0 {
                // A broken pipe: every writer has gone.
                return (bytes, cut);
            }
            let got = got as usize;
            let room = LONGEST_OUTPUT.saturating_sub(bytes.len());
            if got > room {
                cut = true;
            }
            bytes.extend_from_slice(&buffer[..got.min(room)]);
        }
    }

    /// A warm process: waits for its test's index on its input, runs that one test and exits
    /// with its code. An input that ends first (the server let it go) exits with 0, unrun.
    pub fn child(tests: &'static [&'static test::TestDescAndFn]) -> ! {
        // SAFETY: before any thread of this process starts.
        unsafe { std::env::remove_var(SOCKET) };
        let mut index = [0u8; 4];
        if std::io::stdin().read_exact(&mut index).is_err() {
            std::process::exit(0);
        }
        let index = u32::from_le_bytes(index) as usize;
        let code = match tests.get(index) {
            Some(test) => super::one::run(test, mark, exit_now),
            None => {
                eprintln!("blaze's fork server: the binary has {} tests, and no test {}", tests.len(), index);
                1
            }
        };
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        std::process::exit(code)
    }

    /// Nothing: Windows' sandbox keeps no record of what one test reads.
    fn mark(_name: &str) {}

    fn exit_now(code: i32) {
        let _ = std::io::stderr().flush();
        std::process::exit(code)
    }
}
