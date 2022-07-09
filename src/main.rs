use gallagher_rs::{gallagher_decode, gallagher_encode, invert_bits, Credential};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = &args[1];

    match mode.as_str() {
        "dec" => cli_decode(&args[2]),
        "enc" => cli_encode(&Credential {
            region: args[2].parse().unwrap(),
            facility: args[3].parse().unwrap(),
            card: args[4].parse().unwrap(),
            issue: args[5].parse().unwrap(),
        }),
        _ => println!(":("),
    }
}

fn cli_decode(cb: &str) {
    let credential_bytes = hex::decode(cb).unwrap();
    let credential = gallagher_decode(&credential_bytes);
    println!("{}", credential);
}

fn cli_encode(credential: &Credential) {
    let credential_bytes = gallagher_encode(&credential);
    let reparsed_credential = gallagher_decode(&credential_bytes);
    println!("{}", reparsed_credential);
    println!("{}{}", hex::encode_upper(&credential_bytes), hex::encode_upper(invert_bits(&credential_bytes)));
    // println!("hf mf esetblk --blk 60 -d {}{}", hex::encode_upper(&credential_bytes), hex::encode_upper(invert_bits(&credential_bytes)));
    // println!("hf mf sim --1k")
}
