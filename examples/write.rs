use stun_proto::*;

/**
    In this example, we are creating the same attribute
    that is used in the read.rs example.
*/
fn main() {
    let mut buf = [0u8; 28];

    let mut writer = rfc3489::Writer::new(&mut buf);
    writer.set_message_type(rfc3489::MessageType::BindingRequest).unwrap();
    writer.set_transaction_id(1).unwrap();
    writer.add_attr(rfc3489::WriterAttribute::ChangeRequest {change_ip: true, change_port: true}).unwrap();
    let bytes_used = writer.finish().unwrap();

    // this is the same attribute as in the read.rs example
    let req = [
        0x00, 0x01,             // type: Binding Request
        0x00, 0x08,             // length: 8 (header does not count)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // transaction id: 1 (16 bytes total)
        0x00, 0x03,             // attribute type: Change Request
        0x00, 0x04,             // attribute length: 4
        0x00, 0x00, 0x00, 0x60, // request to change both the IP and port
    ];

    assert_eq!(buf.len(), bytes_used as usize);
    assert_eq!(req, buf);
}