
use ffi_interface::verify_execution_witness;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};

#[derive(Deserialize)]
struct Input {
    root: String,
    witness_json: String,
}

#[derive(Serialize)]
struct Output {
    valid: bool,
    error: Option<String>,
}

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() { continue; }
        let out = match serde_json::from_str::<Input>(&line) {
            Err(e) => Output { valid: false, error: Some(e.to_string()) },
            Ok(inp) => {
                let ok = verify_execution_witness(&inp.root, &inp.witness_json);
                Output { valid: ok, error: None }
            }
        };
        println!("{}", serde_json::to_string(&out).unwrap());
    }
}
