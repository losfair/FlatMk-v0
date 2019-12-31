use goblin::elf::{program_header::PT_LOAD, Elf};
use std::fs::File;
use std::io::{Read, Write};

pub fn load(image: &[u8], base: u64, max_size: u64) -> (Vec<u8>, u64) {
    let elf = Elf::parse(image).unwrap();
    let mut out: Vec<u8> = Vec::new();

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_vaddr < base || ph.p_vaddr - base > max_size {
            continue;
        }
        let data = &image[ph.p_offset as usize..];
        let data = &data[..ph.p_filesz as usize];
        let out_start = (ph.p_vaddr - base) as usize;
        let out_end = (ph.p_vaddr - base + ph.p_filesz) as usize;
        if out_end > out.len() {
            out.resize(out_end, 0);
        }
        out[out_start..out_end].copy_from_slice(data);
    }

    // Pad to page size.
    while out.len() % 4096 != 0 {
        out.push(0);
    }

    (out, elf.header.e_entry)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let in_elf = args[1].clone();
    let out_prefix = args[2].clone();

    let mut in_body: Vec<u8> = Vec::new();
    {
        let mut f = File::open(&in_elf).unwrap();
        f.read_to_end(&mut in_body).unwrap();
    }

    let (body, entry) = load(&in_body, 0x20000000, 1048576 * 128);

    let mut out_body = File::create(out_prefix.clone() + ".img").unwrap();
    out_body.write_all(&body).unwrap();

    let mut out_decl = File::create(out_prefix.clone() + ".decl.rs").unwrap();
    write!(
        out_decl,
        "type RootImageBytes = [u8; {}];\nconst ROOT_ENTRY: u64 = {};\n",
        body.len(),
        entry
    )
    .unwrap();

    println!("OK");
}
