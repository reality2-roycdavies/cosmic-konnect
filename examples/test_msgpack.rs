use cosmic_konnect::ckp::message::{Identity, DeviceType, Capability, MessageType, Message, MessageFlags};

fn main() {
    let id = Identity::new(
        "test-id".to_string(),
        "Test".to_string(),
        DeviceType::Desktop,
        17161,
    );
    
    let msg = Message::Identity(id);
    let bytes = msg.encode(MessageFlags::default()).unwrap();
    
    println!("Full packet ({} bytes):", bytes.len());
    println!("Header: {:02x?}", &bytes[0..8]);
    println!("Payload: {:02x?}", &bytes[8..]);
    println!("Payload first byte: 0x{:02x} ({})", bytes[8], bytes[8]);
}
