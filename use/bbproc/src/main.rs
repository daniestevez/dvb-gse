use bytes::Bytes;
use std::path::Path;
use std::fs;
use std::process;

fn main() {
    env_logger::init();

    let path = Path::new("sample.bin");
    if !path.exists() {
        eprintln!("File data.bin not found in current directory");
        process::exit(1);
    }

    let raw: Vec<u8> = fs::read(path).expect("failed to read data.bin");
    let bbframe = Bytes::copy_from_slice(&raw);

    let mut defrag = dvb_gse::gsepacket::GSEPacketDefrag::new();

 
    let result = defrag.defragment(&bbframe);

    match result {
        Ok(pdus) => {
            for pdu in pdus {
                let proto = pdu.protocol_type();
                let data = pdu.data();
                println!("PDU: protocol=0x{:04x}, len={} bytes", proto, data.len());
 
                std::fs::write(format!("pdu_{:04x}_{}.bin", proto, data.len()), &data[..]).ok();
            }
        }
        Err(e) => {
            eprintln!("Failed to defragment BBFRAME: {}", e);
        }
    }
}


// use bytes::Bytes;
// use std::path::Path;
// use std::fs;
// use std::process;

// fn main() {
//     env_logger::init();

//     let path = Path::new("sample.bin");
//     if !path.exists() {
//         eprintln!("File data.bin not found in current directory");
//         process::exit(1);
//     }

//     let raw: Vec<u8> = fs::read(path).expect("failed to read data.bin");
//     let bbframe = Bytes::copy_from_slice(&raw);

//     let mut defrag = dvb_gse::gsepacket::GSEPacketDefrag::new();

//     let result = defrag.defragment(&bbframe);

//     match result {
//         Ok(pdus) => {
        
//             let out_dir = Path::new("/home/ordi/Desktop/");
//             if !out_dir.exists() {
//                 fs::create_dir(out_dir).expect("failed to create pdus directory");
//             }

//             for (i, pdu) in pdus.enumerate() {
//                 let proto = pdu.protocol_type();
//                 let data = pdu.data();
//                 println!("PDU: protocol=0x{:04x}, len={} bytes", proto, data.len());

              
//                 let filename = out_dir.join(format!("pdu_{:04x}_{}_{}.bin", proto, data.len(), i));
//                 fs::write(&filename, &data[..]).ok();
//                 println!("  saved -> {}", filename.display());
//             }
//         }
//         Err(e) => {
//             eprintln!("Failed to defragment BBFRAME: {}", e);
//         }
//     }
// }

// use bytes::Bytes;
// use std::path::Path;
// use std::fs;
// use std::process;

// fn main() {
//     env_logger::init();

//     let path = Path::new("sample.bin");
//     if !path.exists() {
//         eprintln!("File bbframe.bin not found in current directory");
//         process::exit(1);
//     }

//     let raw: Vec<u8> = fs::read(path).expect("failed to read bbframe.bin");
//     let bbframe = Bytes::copy_from_slice(&raw);

//     let mut defrag = dvb_gse::gsepacket::GSEPacketDefrag::new();

//     let result = defrag.defragment(&bbframe);

//     match result {
//         Ok(pdus) => {
//             let out_dir = Path::new("/home/ordi/Desktop/");
//             if !out_dir.exists() {
//                 fs::create_dir(out_dir).expect("failed to create output directory");
//             }

//             for (i, pdu) in pdus.into_iter().enumerate() {
//                 let proto = pdu.protocol_type();
//                 let data = pdu.data();

 
//                 println!("PDU #{} -> protocol=0x{:04x}, len={} bytes", i, proto, data.len());

/ 
//                 let preview_len = data.len().min(16);
//                 println!("   first {} bytes: {:02x?}", preview_len, &data[..preview_len]);

/ 
//                 let filename = out_dir.join(format!("pdu_{:04x}_{}_{}.bin", proto, data.len(), i));
//                 fs::write(&filename, &data[..]).ok();
//                 println!("   saved -> {}\n", filename.display());
//             }
//         }
//         Err(e) => {
//             eprintln!("Failed to defragment BBFRAME: {}", e);
//         }
//     }
// }
