#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;

#[cfg(target_os = "linux")]
use std::os::unix::net::SocketAddr;

pub fn ready() {
  if let Err(error) = notify("READY=1") {
    eprintln!("systemd notify failed: {error}");
  }
}

#[cfg(unix)]
fn notify(message: &str) -> std::io::Result<()> {
  let Some(socket_path) = std::env::var_os("NOTIFY_SOCKET") else {
    return Ok(());
  };

  let socket = UnixDatagram::unbound()?;

  #[cfg(target_os = "linux")]
  {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    let path = socket_path.as_os_str().as_bytes();
    if path.is_empty() || (path[0] != b'/' && path[0] != b'@') {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "NOTIFY_SOCKET must start with '/' or '@'",
      ));
    }

    if let Some(name) = path.strip_prefix(b"@") {
      let addr = SocketAddr::from_abstract_name(name)?;
      socket.send_to_addr(message.as_bytes(), &addr)?;
    } else {
      socket.send_to(message.as_bytes(), Path::new(&socket_path))?;
    }
  }

  #[cfg(not(target_os = "linux"))]
  {
    use std::path::Path;
    socket.send_to(message.as_bytes(), Path::new(&socket_path))?;
  }
  Ok(())
}

#[cfg(not(unix))]
fn notify(_: &str) -> std::io::Result<()> {
  Ok(())
}
