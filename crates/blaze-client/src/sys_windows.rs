//! One wait for socket readiness or a wake from another thread. An auto-reset event coalesces
//! wakes without allocating a pair of AF_UNIX sockets on disk for every client connection.

use blaze_core::wait::{self, Deadline, Monotonic, Once, WaitError, Waited};
use std::{
    io::{self, Write as _},
    os::windows::io::{AsRawHandle as _, AsRawSocket as _, FromRawHandle as _, OwnedHandle},
    sync::Arc,
};
pub(crate) use uds_windows::UnixStream;
use windows_sys::Win32::{
    Foundation::WAIT_TIMEOUT,
    Networking::WinSock::{
        FD_CLOSE, FD_READ, FD_WRITE, WSAEnumNetworkEvents, WSAEventSelect, WSAGetLastError,
        WSANETWORKEVENTS,
    },
    System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects},
};

fn event(manual: bool) -> io::Result<OwnedHandle> {
    // SAFETY: unnamed non-inheritable event; the handle is owned only on success.
    let h = unsafe { CreateEventW(std::ptr::null(), i32::from(manual), 0, std::ptr::null()) };
    if h.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }
}
fn socket_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
#[derive(Clone, Debug)]
pub struct Waker(Arc<OwnedHandle>);
impl Waker {
    pub fn wake(&self) -> io::Result<()> {
        // SAFETY: the Arc keeps the event open; the wait consumes one or more wakes.
        if unsafe { SetEvent(self.0.as_raw_handle()) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
pub(crate) struct Readiness {
    wake: Waker,
    network: OwnedHandle,
}
impl Readiness {
    pub(crate) fn new(stream: &UnixStream) -> io::Result<Self> {
        let network = event(true)?;
        // SAFETY: the socket and event are open for registration. Winsock sets the event
        // on read, close, and when a send that would block can progress (not every turn).
        if unsafe {
            WSAEventSelect(
                stream.as_raw_socket() as usize,
                network.as_raw_handle() as _,
                (FD_READ | FD_WRITE | FD_CLOSE) as i32,
            )
        } != 0
        {
            return Err(socket_error());
        }
        Ok(Self { wake: Waker(Arc::new(event(false)?)), network })
    }
    pub(crate) fn waker(&self) -> io::Result<Waker> {
        Ok(self.wake.clone())
    }
    pub(crate) fn wait(
        &mut self,
        socket: Option<(&UnixStream, bool)>,
        deadline: Deadline,
        clock: &Monotonic,
    ) -> Result<Waited<(bool, bool)>, WaitError> {
        let handles = [self.wake.0.as_raw_handle(), self.network.as_raw_handle()];
        wait::until("a client wake or its socket", clock, deadline.finite(), |left| {
            let ms = left.map_or(u32::MAX, |d| {
                d.as_nanos().div_ceil(1_000_000).min(u128::from(u32::MAX - 1)) as u32
            });
            // SAFETY: both handles live across the wait. With no socket, only a wake is watched.
            match unsafe {
                WaitForMultipleObjects(1 + u32::from(socket.is_some()), handles.as_ptr(), 0, ms)
            } {
                0 => Ok(Once::Ready((true, false))),
                1 => {
                    let mut events = WSANETWORKEVENTS::default();
                    let (s, _) = socket.expect("network event watched");
                    // SAFETY: atomically take this socket's events and reset its event; one reader.
                    if unsafe {
                        WSAEnumNetworkEvents(
                            s.as_raw_socket() as usize,
                            handles[1] as _,
                            &mut events,
                        )
                    } != 0
                    {
                        return Err(socket_error());
                    }
                    Ok(Once::Ready((
                        false,
                        events.lNetworkEvents & ((FD_READ | FD_CLOSE) as i32) != 0,
                    )))
                }
                WAIT_TIMEOUT => Ok(Once::TimedOut),
                _ => Err(io::Error::last_os_error()),
            }
        })
    }
}
pub(crate) fn send(mut stream: &UnixStream, bytes: &[u8]) -> io::Result<usize> {
    stream.write(bytes)
}
pub(crate) fn stderr_columns() -> Option<u16> {
    None
} // same as cli::place on Windows
