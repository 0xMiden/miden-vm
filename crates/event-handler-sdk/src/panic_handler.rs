//! A panic handler that forwards the panic message to the host through `fail`.

use core::fmt::Write;

use miden_event_handler_abi::guest;

/// A fixed-size message buffer; text past the capacity is dropped.
struct MsgBuf {
    data: [u8; 512],
    len: usize,
}

impl Write for MsgBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.data.len() - self.len;
        let take = s.len().min(room);
        self.data[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut buf = MsgBuf { data: [0; 512], len: 0 };
    let _ = write!(buf, "guest panic: {info}");
    // The buffer may end inside a multi-byte character; the host decodes the bytes lossily.
    // SAFETY: the pointer and the length come from `buf`, which lives until this call diverges,
    // and `MsgBuf::write_str` keeps `len` inside the capacity, so the host reads an initialized
    // range of the guest memory.
    unsafe { guest::fail(buf.data.as_ptr(), buf.len as u32) }
}
