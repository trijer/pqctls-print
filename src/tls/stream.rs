use std::io::{Read, Write};
use std::net::TcpStream;

use super::types::HandshakeMessage;
use super::handshake::{parse_handshake_type, parse_handshake_fields};

pub struct TrackedStream {
    inner: TcpStream,
    messages: Vec<HandshakeMessage>,
    sequence: usize,
}

impl TrackedStream {
    pub fn new(stream: TcpStream) -> Self {
        TrackedStream {
            inner: stream,
            messages: Vec::new(),
            sequence: 0,
        }
    }

    pub fn extract_messages(self) -> Vec<HandshakeMessage> {
        self.messages
    }

    fn extract_tls_messages(&mut self, data: &[u8], is_write: bool) {
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let content_type = data[pos];
            let _version = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
            let length = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;

            pos += 5;

            if pos + length > data.len() {
                break;
            }

            match content_type {
                22 => {
                    let mut msg_pos = 0;
                    while msg_pos + 4 <= length {
                        let msg_type = data[pos + msg_pos];
                        let msg_length = u32::from_be_bytes([
                            0,
                            data[pos + msg_pos + 1],
                            data[pos + msg_pos + 2],
                            data[pos + msg_pos + 3],
                        ]) as usize;

                        let (type_name, description) = parse_handshake_type(msg_type);
                        let total_msg_size = msg_length + 4;

                        let direction = if is_write {
                            "Client → Server".to_string()
                        } else {
                            "Server → Client".to_string()
                        };

                        let payload_start = pos + msg_pos + 4;
                        let payload_end = payload_start + msg_length;
                        let fields = if payload_end <= data.len() {
                            parse_handshake_fields(msg_type, &data[payload_start..payload_end])
                        } else {
                            None
                        };

                        self.messages.push(HandshakeMessage {
                            sequence: self.sequence,
                            direction,
                            message_type: type_name,
                            size: total_msg_size,
                            description,
                            fields,
                            inferred: false,
                        });

                        self.sequence += 1;
                        msg_pos += total_msg_size;
                    }
                }
                20 => {
                    let direction = if is_write {
                        "Client → Server".to_string()
                    } else {
                        "Server → Client".to_string()
                    };

                    self.messages.push(HandshakeMessage {
                        sequence: self.sequence,
                        direction,
                        message_type: "ChangeCipherSpec".to_string(),
                        size: length,
                        description: "Cipher suite change notification (TLS 1.2)".to_string(),
                        fields: None,
                        inferred: false,
                    });

                    self.sequence += 1;
                }
                _ => {}
            }

            pos += length;
        }
    }
}

impl Read for TrackedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.extract_tls_messages(&buf[..n], false);
        }
        Ok(n)
    }
}

impl Write for TrackedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extract_tls_messages(buf, true);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
