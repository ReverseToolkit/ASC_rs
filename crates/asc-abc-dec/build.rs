use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=resources/opcodes.tsv");
    let table = fs::read_to_string("resources/opcodes.tsv").expect("read checked-in opcode table");
    let mut generated =
        String::from("fn opcode(code: u16) -> Option<Opcode> { Some(match code {\n");
    for row in table
        .lines()
        .filter(|row| !row.starts_with('#') && !row.is_empty())
    {
        let parts: Vec<_> = row.split('\t').collect();
        assert_eq!(parts.len(), 4, "opcode table needs four columns");
        let code: u16 = parts[0].parse().expect("numeric opcode");
        generated.push_str(&format!(
            "{code} => Opcode {{ name: {:?}, format: {:?}, flags: {} }},\n",
            parts[1], parts[2], parts[3]
        ));
    }
    generated.push_str("_ => return None,\n}) }\n");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out.join("opcodes.rs"), generated).expect("write generated opcode table");
}
