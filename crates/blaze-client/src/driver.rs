//! The blocking driver of [`Mux`] over the daemon's Unix socket: it reads, writes and waits,
//! and decides nothing. Every wait is blaze-core's one deadline wait ([`wait::readable`]) on
//! the socket and the client's wake pipe, to the earlier of the caller's deadline and the next
//! deadline of a request under way.

use std::{
    collections::VecDeque,
    io::{self, Read as _},
    path::{Path, PathBuf},
    time::Duration,
};

pub use crate::sys::Waker;
use crate::sys::{Readiness, UnixStream};
use blaze_api::{Rebuilt, Request, Response, Status};
use blaze_core::wait::{Clock as _, Deadline, Monotonic, Waited};

use crate::{
    Error,
    ask::{self, Answer, Call, Method, Options, Outcome, WhyOptions},
    mux::{self, End, Event, Fault, Mux},
    start::{self, Homes, Start},
    sys,
};

/// The most bytes one read takes.
const RECEIVE: usize = 64 << 10;

/// How a client connects.
#[derive(Clone, Copy, Debug)]
pub struct Connect<'a> {
    /// The daemon's home (`BLAZE_HOME`'s meaning); `None` for the environment's.
    pub home: Option<&'a Path>,
    /// The `blaze` program a daemon is started with; `None` for the one beside this program,
    /// else the first on `PATH`.
    pub blaze: Option<&'a Path>,
    pub start: Start,
    /// How long the connect may take, the daemon's start with it.
    pub within: Duration,
}

/// What [`Client::next`] waited for.
#[derive(Debug)]
pub enum Next {
    Event(Event),
    /// A [`Waker`] woke the wait.
    Woken,
    /// The caller's deadline passed.
    Deadline,
}

/// A connection to the daemon.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    mux: Mux,
    clock: Monotonic,
    /// Events of other requests that came while [`Client::request`] waited for its own.
    kept: VecDeque<Event>,
    ready: Readiness,
    socket: PathBuf,
    /// What each read reads into.
    buffer: Vec<u8>,
}

impl Client {
    /// Connects to the daemon of `home` (`None`: the environment's), starting it when nothing
    /// listens ([`start`]), within `within`.
    pub fn connect(home: Option<&Path>, within: Duration) -> Result<Client, Error> {
        Client::connect_with(&Connect { home, blaze: None, start: Start::IfMissing, within })
    }

    pub fn connect_with(connect: &Connect<'_>) -> Result<Client, Error> {
        let clock = Monotonic::new();
        let deadline = Deadline::after(clock.now(), connect.within);
        // The environment is read here, where a client begins, and nowhere after.
        let homes = Homes::of(connect.home, |name| std::env::var_os(name)).map_err(Error::Asked)?;
        let _span = tracing::info_span!(target: "blaze", "client: connect to the daemon").entered();
        // clone: error paths below name the socket.
        let socket = homes.socket.clone();
        let failed = |error| Error::Connect { socket: socket.clone(), error };
        let stream = match UnixStream::connect(&homes.socket) {
            Ok(stream) => stream,
            Err(error) if !start::nothing_listens(&error) => return Err(failed(error)),
            Err(_) if connect.start == Start::Never => {
                return Err(Error::NoDaemon { socket });
            }
            Err(_) => {
                let this = std::env::current_exe().ok();
                let path = std::env::var_os("PATH");
                let blaze = start::program(connect.blaze, this.as_deref(), path.as_deref())
                    .map_err(Error::Start)?;
                start::daemon(&homes, &blaze, deadline, &clock).map_err(Error::Start)?;
                UnixStream::connect(&homes.socket).map_err(failed)?
            }
        };
        stream.set_nonblocking(true).map_err(failed)?;
        let ready = Readiness::new(&stream).map_err(failed)?;
        Ok(Client {
            stream,
            mux: Mux::new(),
            clock,
            // alloc: none until a request waits while another's events come.
            kept: VecDeque::new(),
            ready,
            socket: homes.socket,
            // alloc: once per connection, every read's.
            buffer: vec![0; RECEIVE],
        })
    }

    /// Where the daemon listens.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// A handle another thread wakes this client's [`Client::next`] with.
    pub fn waker(&self) -> io::Result<Waker> {
        // clone: the shared flag, once per waker.
        self.ready.waker()
    }

    /// Sends `request`, to end within `within`: its id, under which [`Client::next`] tells its
    /// responses and its end. Other requests may be under way.
    pub fn send(&mut self, request: &Request, within: Duration) -> Result<u64, Error> {
        let deadline = Deadline::after(self.clock.now(), within);
        let id = self.mux.send(request, deadline)?;
        self.flush();
        Ok(id)
    }

    /// The next event of any request under way, a wake, or the passing of `within`. Once the
    /// connection is over and every event of it is told, the fault that ended it.
    pub fn next(&mut self, within: Duration) -> Result<Next, Error> {
        if let Some(event) = self.kept.pop_front() {
            return Ok(Next::Event(event));
        }
        let until = Deadline::after(self.clock.now(), within);
        self.turn(until)
    }

    /// Sends `request` and hands each of its responses to `on` until it ends, within `within`:
    /// its `Done`'s `ok`. Events of other requests that come meanwhile are kept for
    /// [`Client::next`].
    pub fn request(
        &mut self,
        request: &Request,
        within: Duration,
        mut on: impl FnMut(Response),
    ) -> Result<bool, Error> {
        let id = self.send(request, within)?;
        let _span = tracing::info_span!(
            target: "blaze",
            "client: wait for the daemon's answer to the request",
            request = mux::named(request),
            id,
        )
        .entered();
        // Bounded: the request ends by its deadline, which the mux holds it to.
        loop {
            match self.turn(Deadline::NEVER)? {
                Next::Event(Event::Response { id: of, response }) if of == id => on(response),
                Next::Event(Event::Ended { id: of, how }) if of == id => {
                    return match how {
                        End::Done { ok } => Ok(ok),
                        End::Failed(fault) => Err(Error::Fault(fault)),
                    };
                }
                Next::Event(other) => self.kept.push_back(other),
                Next::Woken | Next::Deadline => {}
            }
        }
    }

    /// `blaze build` of `options`: each response to `on_event` as it comes, then what the
    /// build came to.
    pub fn build(
        &mut self,
        options: &Options,
        on_event: impl FnMut(&Response),
    ) -> Result<Outcome, Error> {
        self.command(Method::Build, options, on_event)
    }

    /// `blaze check` of `options`.
    pub fn check(
        &mut self,
        options: &Options,
        on_event: impl FnMut(&Response),
    ) -> Result<Outcome, Error> {
        self.command(Method::Check, options, on_event)
    }

    /// The tests of `options`, run in the daemon ([`Request::Test`]): every one its filter
    /// selects, or with `reached` those the view's change reached.
    pub fn test(
        &mut self,
        options: &Options,
        on_event: impl FnMut(&Response),
    ) -> Result<Outcome, Error> {
        self.command(Method::Test, options, on_event)
    }

    /// `blaze why`: what the last build computed again, and why.
    pub fn why(&mut self, options: &WhyOptions) -> Result<Rebuilt, Error> {
        let within = Duration::from_millis(options.within_ms);
        match self.call(Method::Why, &ask::why(options), within, |_| {})? {
            Answer::Rebuilt(rebuilt) => Ok(*rebuilt),
            other => Err(ask::unexpected(Method::Why, &other)),
        }
    }

    /// What the daemon is doing.
    pub fn status(&mut self, within: Duration) -> Result<Status, Error> {
        match self.call(Method::Status, &Request::Status, within, |_| {})? {
            Answer::Status(status) => Ok(*status),
            other => Err(ask::unexpected(Method::Status, &other)),
        }
    }

    /// Hangs up: every request under way ends with [`Fault::Closed`].
    pub fn close(mut self) {
        self.mux.broke(Fault::Closed);
    }

    /// Ends every request under way with [`Fault::Closed`] and takes no more; the events are
    /// [`Client::next`]'s to tell.
    pub fn shut(&mut self) {
        self.mux.broke(Fault::Closed);
    }

    /// Waits for a wake alone, with the connection over, within `within`: whether one came.
    pub fn idle(&mut self, within: Duration) -> Result<bool, Error> {
        let until = Deadline::after(self.clock.now(), within);
        match self.ready.wait(None, until, &self.clock) {
            Ok(Waited::Ready(_)) => Ok(true),
            Ok(Waited::Deadline) => Ok(false),
            // alloc: error path, a wait that failed.
            Err(error) => Err(Error::Fault(Fault::Io { what: error.to_string() })),
        }
    }

    fn command(
        &mut self,
        method: Method,
        options: &Options,
        on_event: impl FnMut(&Response),
    ) -> Result<Outcome, Error> {
        let env = crate::place::env_of(options.env.as_deref()).map_err(Error::Asked)?;
        let request = ask::request(method, options, &env).map_err(Error::Asked)?;
        let within = Duration::from_millis(options.within_ms);
        match self.call(method, &request, within, on_event)? {
            Answer::Outcome(outcome) => Ok(*outcome),
            other => Err(ask::unexpected(method, &other)),
        }
    }

    fn call(
        &mut self,
        method: Method,
        request: &Request,
        within: Duration,
        mut on_event: impl FnMut(&Response),
    ) -> Result<Answer, Error> {
        let mut call = Call::new(method);
        let ok = self.request(request, within, |response| {
            on_event(&response);
            call.take(response);
        })?;
        call.finish(ok)
    }

    /// One wait and what came of it, to `until`.
    fn turn(&mut self, until: Deadline) -> Result<Next, Error> {
        // Bounded: each turn tells an event, ends at a deadline that passed, or waits to the
        // earlier of `until` and the next request's deadline, after which that request ends.
        loop {
            if let Some(event) = self.mux.poll() {
                return Ok(Next::Event(event));
            }
            if let Some(fault) = self.mux.broken() {
                // clone: error path, the connection is over.
                return Err(Error::Fault(fault.clone()));
            }
            let now = self.clock.now();
            self.mux.tick(now);
            self.flush();
            if let Some(event) = self.mux.poll() {
                return Ok(Next::Event(event));
            }
            if self.mux.broken().is_some() {
                continue;
            }
            if until.passed(now) {
                return Ok(Next::Deadline);
            }
            let deadline = self.mux.next_deadline().map_or(until, |it| it.min(until));
            let waited = {
                let _span = tracing::trace_span!(
                    target: "blaze",
                    "client: wait for the daemon's socket",
                    requests = self.mux.open(),
                )
                .entered();
                self.ready.wait(
                    Some((&self.stream, !self.mux.outgoing().is_empty())),
                    deadline,
                    &self.clock,
                )
            };
            match waited {
                Ok(Waited::Ready((true, _))) => return Ok(Next::Woken),
                Ok(Waited::Ready((false, true))) => self.fill(),
                Ok(Waited::Ready((false, false))) => {}
                Ok(Waited::Deadline) => continue,
                Err(error) => {
                    // alloc: error path, a wait that failed.
                    self.mux.broke(Fault::Io {
                        what: format!("waiting on the daemon's socket: {error}"),
                    });
                    continue;
                }
            }
        }
    }

    /// One read of the daemon's bytes into the mux.
    fn fill(&mut self) {
        match self.stream.read(&mut self.buffer) {
            Ok(0) => self.mux.hung_up(),
            Ok(read) => self.mux.received(&self.buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => self.mux.hung_up(),
            Err(error) => {
                // alloc: error path, a read that failed.
                let what =
                    format!("reading the daemon's socket {}: {error}", self.socket.display());
                self.mux.broke(Fault::Io { what });
            }
        }
    }

    /// Writes what the socket takes of the frames to send, without waiting.
    fn flush(&mut self) {
        // Bounded: each turn writes at least one byte of what is left, or ends.
        while !self.mux.outgoing().is_empty() {
            match sys::send(&self.stream, self.mux.outgoing()) {
                Ok(0) => return,
                Ok(sent) => self.mux.wrote(sent),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return self.mux.hung_up();
                }
                Err(error) => {
                    // alloc: error path, a write that failed.
                    let what = format!(
                        "writing to the daemon's socket {}: {error}",
                        self.socket.display()
                    );
                    return self.mux.broke(Fault::Io { what });
                }
            }
        }
    }
}
