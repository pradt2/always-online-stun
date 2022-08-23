use stun_proto::*;

/**
    In this example, we are reading an example
    BindingRequest with a ChangeRequest attribute.
*/
fn main() {

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

    let reader = rfc3489::Reader::new(&req);

    let msg_type = reader.get_message_type().unwrap();
    assert_eq!(rfc3489::MessageType::BindingRequest, msg_type);

    let transaction_id = reader.get_transaction_id().unwrap();
    assert_eq!(1u128, transaction_id);

    let attr = reader.get_attributes().next().unwrap().unwrap();
    if let rfc3489::ReaderAttribute::ChangeRequest(change_request) = attr {
        assert_eq!(true, change_request.get_change_ip().unwrap());
        assert_eq!(true, change_request.get_change_port().unwrap());
    }

}