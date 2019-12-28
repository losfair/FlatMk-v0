//! Generates API bindings in different languages from TOML specification.

#[macro_use]
extern crate serde_derive;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;
use structopt::StructOpt;

/// Generates FlatMk kernel API bindings from specification.
#[derive(StructOpt, Debug)]
#[structopt(name = "FlatMk API Codegen")]
struct CliArgs {
    /// Path to input specification file.
    #[structopt(short = "i", long)]
    input: String,

    /// Path to output file.
    #[structopt(short = "o", long)]
    output: String,

    /// Target language to generate bindings for.
    #[structopt(long, default_value = "rust")]
    language: TargetLanguage,

    /// Whether to generate enumeration definitions.
    #[structopt(long = "generate-enums")]
    generate_enums: bool,
}

/// Target language to generate bindings for.
#[derive(Copy, Clone, Debug)]
enum TargetLanguage {
    C,
    Rust,
}

impl FromStr for TargetLanguage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, &'static str> {
        Ok(match s {
            "c" => TargetLanguage::C,
            "rust" => TargetLanguage::Rust,
            _ => return Err("Unknown target language"),
        })
    }
}

impl TargetLanguage {
    fn format_multiline_comment(&self, comment: &str, out: &mut String) {
        for line in comment.split("\n").map(|x| x.trim()) {
            match *self {
                TargetLanguage::C => {
                    out.push_str("// ");
                }
                TargetLanguage::Rust => {
                    out.push_str("/// ");
                }
            }
            out.push_str(line);
            out.push_str("\n");
        }
    }
}

/// The specification.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Spec {
    /// Enumerations.
    enums: BTreeMap<String, Enum>,

    /// Bitflags.
    bitflags: BTreeMap<String, BitflagSet>,

    /// Types derived from `CPtr`.
    types: BTreeMap<String, Type>,
}

/// An enumeration with value type `i64`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Enum {
    /// Enum description.
    description: Option<String>,

    /// Enum variants.
    variants: BTreeMap<String, i64>,
}

/// A set of bits.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct BitflagSet {
    /// Bitflag set description.
    description: Option<String>,

    /// Bits.
    bits: BTreeMap<String, u8>,
}

/// A type derived from `CPtr`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Type {
    /// Type description.
    description: Option<String>,

    /// Types that can be converted from this type.
    into: Vec<String>,

    /// The base enum for this type. Used in CapInvokeArgument.
    base_enum: Option<String>,

    /// Methods of this type.
    methods: BTreeMap<String, Method>,
}

/// A generated method.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Method {
    /// Method description.
    description: Option<String>,

    /// Input arguments.
    in_args: Vec<MethodArgument>,

    /// Arguments passed to capability invocation.
    out_args: Vec<CapInvokeArgument>,
}

/// An argument to a generated method.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct MethodArgument {
    /// Description.
    description: Option<String>,

    /// Argument name.
    name: String,

    /// Kind of the argument.
    kind: ArgumentKind,
}

/// Kind of a method argument.
#[derive(Serialize, Deserialize, Clone, Debug)]
enum ArgumentKind {
    /// A 64-bit signed integer.
    I64,

    /// A 64-bit unsigned integer.
    U64,

    /// A reference to a capability pointer.
    CPtrRef,

    /// A reference to another wrapper type around a capability pointer.
    TypeRef(String),

    /// A bitflag set.
    BitflagSet(String),
}

/// An argument for capability invocation.
#[derive(Serialize, Deserialize, Clone, Debug)]
enum CapInvokeArgument {
    /// A 64-bit signed constant.
    Constant(i64),

    /// A variant in the `base_enum`.
    EnumVariant(String),

    /// An input argument.
    Input(String),
}

fn main() {
    let args = CliArgs::from_args();
    let mut spec = String::new();
    File::open(&args.input)
        .expect("Cannot open specification file.")
        .read_to_string(&mut spec)
        .expect("Cannot read specification file.");

    let spec: Spec = toml::from_str(&spec).expect("Cannot parse specification file.");
    let mut out = String::new();

    out.push_str("// This file is generated by flatmk-codegen. Do not edit.\n\n");

    if args.generate_enums {
        generate_enums(&spec, args.language, &mut out);
    }

    File::create(&args.output)
        .expect("Cannot open output file.")
        .write_all(out.as_bytes())
        .expect("Cannot write output file.");
}

fn generate_enums(spec: &Spec, lang: TargetLanguage, out: &mut String) {
    match lang {
        TargetLanguage::Rust => {
            out.push_str("#[allow(unused_imports)]\nuse num_enum::TryFromPrimitive;\n\n");
        }
        _ => {}
    }

    for (k, v) in &spec.enums {
        if let Some(ref desc) = v.description {
            lang.format_multiline_comment(desc.as_str(), out);
        }
        match lang {
            TargetLanguage::C => {
                out.push_str(format!("enum {} {{\n", k).as_str());
            }
            TargetLanguage::Rust => {
                out.push_str("#[repr(i64)]\n");
                out.push_str("#[derive(Debug, Copy, Clone, TryFromPrimitive)]\n");
                out.push_str(format!("pub enum {} {{\n", k).as_str());
            }
        }
        let mut variants: Vec<(i64, String)> =
            v.variants.iter().map(|(k, v)| (*v, k.clone())).collect();
        variants.sort();
        for (index, key) in variants {
            match lang {
                TargetLanguage::C => {
                    out.push_str(format!("\t{}_{} = {},\n", k, key, index).as_str());
                }
                TargetLanguage::Rust => {
                    out.push_str(format!("\t{} = {},\n", key, index).as_str());
                }
            }
        }
        match lang {
            TargetLanguage::C => {
                out.push_str("};\n\n");
            }
            TargetLanguage::Rust => {
                out.push_str("}\n\n");
            }
        }
    }
}
