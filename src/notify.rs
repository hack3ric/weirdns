#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;

#[cfg(target_os = "linux")]
use std::os::unix::net::SocketAddr;

pub fn ready() {
  notify("READY=1");
}

#[cfg(unix)]
fn notify(message: &str) {
  let Some(socket_path) = std::env::var_os("NOTIFY_SOCKET") else {
    return;
  };

  let Ok(socket) = UnixDatagram::unbound() else {
    return;
  };

  #[cfg(target_os = "linux")]
  {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    let path = socket_path.as_os_str().as_bytes();
    let result = if let Some(name) = path.strip_prefix(b"@") {
      SocketAddr::from_abstract_name(name).and_then(|addr| socket.send_to_addr(message.as_bytes(), &addr).map(|_| ()))
    } else {
      socket.send_to(message.as_bytes(), Path::new(&socket_path)).map(|_| ())
    };

    let _ = result;
  }

  #[cfg(not(target_os = "linux"))]
  {
    use std::path::Path;
    let _ = socket.send_to(message.as_bytes(), Path::new(&socket_path));
  }
}

#[cfg(not(unix))]
fn notify(_: &str) {}
