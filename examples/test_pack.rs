use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Identity {
    #[serde(rename = "type")]
    pub msg_type: u8,
    pub device_id: String,
    pub name: String,
}

fn main() {
    let id = Identity {
        msg_type: 1,
        device_id: "test-id".to_string(),
        name: "Test".to_string(),
    };
    
    // Default to_vec uses arrays (bad)
    let bytes_array = rmp_serde::to_vec(&id).unwrap();
    println!("Array format: {:02x?}", bytes_array);
    println!("First byte: 0x{:02x} (fixarray)", bytes_array[0]);
    
    // Named uses maps (good)
    let bytes_map = rmp_serde::encode::to_vec_named(&id).unwrap();
    println!("\nMap format: {:02x?}", bytes_map);
    println!("First byte: 0x{:02x} (fixmap)", bytes_map[0]);
}
