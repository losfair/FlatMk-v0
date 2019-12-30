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

    /// Whether to generate bitflag definitions.
    #[structopt(long = "generate-bitflags")]
    generate_bitflags: bool,

    /// Whether to generate type definitions.
    #[structopt(long = "generate-types")]
    generate_types: bool,
}

/// Target language to generate bindings for.
#[derive(Copy, Clone, Debug)]
enum TargetLanguage {
    C,
    Rust,
    Markdown,
}

impl FromStr for TargetLanguage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, &'static str> {
        Ok(match s {
            "c" => TargetLanguage::C,
            "rust" => TargetLanguage::Rust,
            "markdown" => TargetLanguage::Markdown,
            _ => return Err("Unknown target language"),
        })
    }
}

impl TargetLanguage {
    fn format_multiline_comment(&self, comment: &str, prefix_tabs: usize, out: &mut String) {
        for line in comment.trim().split("\n").map(|x| x.trim()) {
            for _ in 0..prefix_tabs {
                out.push('\t');
            }
            match *self {
                TargetLanguage::C => {
                    out.push_str("// ");
                }
                TargetLanguage::Rust => {
                    out.push_str("/// ");
                }
                TargetLanguage::Markdown => {}
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

impl ArgumentKind {
    fn fmt_write(&self, lang: TargetLanguage, out: &mut String) {
        match lang {
            TargetLanguage::Rust => match *self {
                ArgumentKind::I64 => {
                    out.push_str("i64");
                }
                ArgumentKind::U64 => {
                    out.push_str("u64");
                }
                ArgumentKind::CPtrRef => {
                    out.push_str("&CPtr");
                }
                ArgumentKind::TypeRef(ref ty) => {
                    out.push_str(format!("&{}", ty).as_str());
                }
                ArgumentKind::BitflagSet(ref ty) => {
                    out.push_str(ty.as_str());
                }
            },
            TargetLanguage::C => match *self {
                ArgumentKind::I64 => {
                    out.push_str("int64_t");
                }
                ArgumentKind::U64 => {
                    out.push_str("uint64_t");
                }
                ArgumentKind::CPtrRef => {
                    out.push_str("CPtr");
                }
                ArgumentKind::TypeRef(ref ty) => {
                    out.push_str(format!("struct {}", ty).as_str());
                }
                ArgumentKind::BitflagSet(_) => {
                    out.push_str("uint64_t");
                }
            },
            TargetLanguage::Markdown => match *self {
                ArgumentKind::I64 => {
                    out.push_str("i64");
                }
                ArgumentKind::U64 => {
                    out.push_str("u64");
                }
                ArgumentKind::CPtrRef => {
                    out.push_str("CPtr");
                }
                ArgumentKind::TypeRef(ref ty) => {
                    out.push_str(format!("Type: {}", ty).as_str());
                }
                ArgumentKind::BitflagSet(ref ty) => {
                    out.push_str(format!("Bitflags: {}", ty).as_str());
                }
            },
        }
    }
}

/// An argument for capability invocation.
#[derive(Serialize, Deserialize, Clone, Debug)]
enum CapInvokeArgument {
    /// A 64-bit signed constant.
    Constant(i64),

    /// A variant of an enum.
    EnumVariant { enum_name: String, variant: String },

    /// An input argument.
    Input(String),
}

impl CapInvokeArgument {
    fn fmt_write(&self, lang: TargetLanguage, in_args: &[MethodArgument], out: &mut String) {
        match *self {
            CapInvokeArgument::Input(ref name) => {
                let input = in_args
                    .iter()
                    .find(|x| x.name == name.as_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "CapInvokeArgument::fmt_write: Cannot find input argument '{}'.",
                            name
                        )
                    });
                match lang {
                    TargetLanguage::Rust => match input.kind {
                        ArgumentKind::I64 => out.push_str(format!("{}", input.name).as_str()),
                        ArgumentKind::U64 => {
                            out.push_str(format!("{} as i64", input.name).as_str())
                        }
                        ArgumentKind::CPtrRef => {
                            out.push_str(format!("{}.index() as i64", input.name).as_str())
                        }
                        ArgumentKind::TypeRef(_) => {
                            out.push_str(format!("{}.cptr().index() as i64", input.name).as_str())
                        }
                        ArgumentKind::BitflagSet(_) => {
                            out.push_str(format!("{}.bits() as i64", input.name).as_str())
                        }
                    },
                    TargetLanguage::C => match input.kind {
                        ArgumentKind::I64
                        | ArgumentKind::U64
                        | ArgumentKind::CPtrRef
                        | ArgumentKind::BitflagSet(_) => {
                            out.push_str(format!("{}", input.name).as_str())
                        }
                        ArgumentKind::TypeRef(_) => {
                            out.push_str(format!("{}.cap", input.name).as_str())
                        }
                    },
                    TargetLanguage::Markdown => {
                        unreachable!("CapInvokeArgument should not be written to Markdown output");
                    }
                }
            }
            CapInvokeArgument::EnumVariant {
                ref enum_name,
                ref variant,
            } => match lang {
                TargetLanguage::Rust => {
                    out.push_str(format!("{}::{} as i64", enum_name, variant).as_str());
                }
                TargetLanguage::C => {
                    out.push_str(format!("{}_{}", enum_name, variant).as_str());
                }
                TargetLanguage::Markdown => {
                    unreachable!("CapInvokeArgument should not be written to Markdown output");
                }
            },
            CapInvokeArgument::Constant(x) => match lang {
                TargetLanguage::Rust => {
                    out.push_str(format!("{}i64", x).as_str());
                }
                TargetLanguage::C => {
                    out.push_str(format!("{}ll", x).as_str());
                }
                TargetLanguage::Markdown => {
                    unreachable!("CapInvokeArgument should not be written to Markdown output");
                }
            },
        }
    }
}

const N_CAP_INVOKE_ARGUMENTS: usize = 4;

fn main() {
    let args = CliArgs::from_args();
    let mut spec = String::new();
    File::open(&args.input)
        .expect("Cannot open specification file.")
        .read_to_string(&mut spec)
        .expect("Cannot read specification file.");

    let spec: Spec = toml::from_str(&spec).expect("Cannot parse specification file.");
    let mut out = String::new();

    match args.language {
        TargetLanguage::Rust | TargetLanguage::C => {
            out.push_str("// This file is generated by flatmk-codegen. Do not edit.\n\n");
        }
        TargetLanguage::Markdown => {
            out.push_str("# FlatMk Capability API Specification\n\n");
            out.push_str("*This file is automatically generated.*\n\n");
        }
    }

    if args.generate_enums {
        generate_enums(&spec, args.language, &mut out);
    }

    if args.generate_bitflags {
        generate_bitflags(&spec, args.language, &mut out);
    }

    if args.generate_types {
        generate_types(&spec, args.language, &mut out);
    }

    File::create(&args.output)
        .expect("Cannot open output file.")
        .write_all(out.as_bytes())
        .expect("Cannot write output file.");
}

fn generate_enums(spec: &Spec, lang: TargetLanguage, out: &mut String) {
    match lang {
        TargetLanguage::Rust => {}
        TargetLanguage::Markdown => {
            out.push_str("## Enums\n\n");
        }
        _ => {}
    }

    for (k, v) in &spec.enums {
        match lang {
            TargetLanguage::C => {
                if let Some(ref desc) = v.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str(format!("enum {} {{\n", k).as_str());
            }
            TargetLanguage::Rust => {
                if let Some(ref desc) = v.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str("#[repr(i64)]\n");
                out.push_str("#[derive(Debug, Copy, Clone, TryFromPrimitive)]\n");
                out.push_str(format!("pub enum {} {{\n", k).as_str());
            }
            TargetLanguage::Markdown => {
                out.push_str(format!("- `{}`\n\n", k).as_str());
                if let Some(ref desc) = v.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str("\n");
                out.push_str("| Variant | Index |\n");
                out.push_str("| ------- | ----- |\n");
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
                TargetLanguage::Markdown => {
                    out.push_str(format!("| {} | {} |\n", key, index).as_str());
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
            TargetLanguage::Markdown => {
                out.push_str("\n");
            }
        }
    }
}

fn generate_bitflags(spec: &Spec, lang: TargetLanguage, out: &mut String) {
    match lang {
        TargetLanguage::Markdown => {
            out.push_str("## Bitflags\n\n");
        }
        _ => {}
    }

    for (set_name, set) in &spec.bitflags {
        match lang {
            TargetLanguage::C => {
                if let Some(ref desc) = set.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
            }
            TargetLanguage::Rust => {
                if let Some(ref desc) = set.description {
                    lang.format_multiline_comment(desc.as_str(), 1, out);
                }
                out.push_str(format!("bitflags! {{\n\tpub struct {}: u64 {{\n", set_name).as_str());
            }
            TargetLanguage::Markdown => {
                out.push_str(format!("- `{}`\n\n", set_name).as_str());
                if let Some(ref desc) = set.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str("\n");
                out.push_str("| Flag | Bit |\n");
                out.push_str("| ------- | ----- |\n");
            }
        }
        let mut bits: Vec<(u8, String)> = set.bits.iter().map(|(k, v)| (*v, k.clone())).collect();
        bits.sort();
        for (bit, flag) in bits {
            match lang {
                TargetLanguage::C => {
                    out.push_str(
                        format!("#define {}_{} (1 << {})\n", set_name, flag, bit).as_str(),
                    );
                }
                TargetLanguage::Rust => {
                    out.push_str(format!("\t\tconst {} = 1 << {};\n", flag, bit).as_str());
                }
                TargetLanguage::Markdown => {
                    out.push_str(format!("| {} | {} |\n", flag, bit).as_str());
                }
            }
        }
        match lang {
            TargetLanguage::C => {
                out.push_str("\n");
            }
            TargetLanguage::Rust => {
                out.push_str("\t}\n}\n\n");
            }
            TargetLanguage::Markdown => {
                out.push_str("\n");
            }
        }
    }
}

fn generate_types(spec: &Spec, lang: TargetLanguage, out: &mut String) {
    match lang {
        TargetLanguage::Markdown => {
            out.push_str("## Types\n\n");
        }
        _ => {}
    }

    for (type_name, type_def) in &spec.types {
        match lang {
            TargetLanguage::C => {
                if let Some(ref desc) = type_def.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str(
                    format!(
                        r#"struct {} {{
    CPtr cap;
}};

struct {} {}_new(CPtr cap) {{
    struct {} result = {{ .cap = cap }};
    return result;
}}
"#,
                        type_name, type_name, type_name, type_name
                    )
                    .as_str(),
                );
            }
            _ => {}
        }
    }

    for (type_name, type_def) in &spec.types {
        match lang {
            TargetLanguage::Rust => {
                if let Some(ref desc) = type_def.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push_str(
                    format!(
                        r#"#[derive(Copy, Clone, Debug)]
pub struct {} {{
    cap: CPtr
}}

impl Into<CPtr> for {} {{
    fn into(self) -> CPtr {{
        self.cap
    }}
}}

impl {} {{
    pub const unsafe fn new(cap: CPtr) -> Self {{
        Self {{
            cap,
        }}
    }}

    pub const fn cptr(&self) -> &CPtr {{
        &self.cap
    }}

"#,
                        type_name, type_name, type_name
                    )
                    .as_str(),
                );
            }
            TargetLanguage::C => {
                // Definition generated in the previous loop.
            }
            TargetLanguage::Markdown => {
                out.push_str(format!("### {}\n\n", type_name).as_str());
                if let Some(ref desc) = type_def.description {
                    lang.format_multiline_comment(desc.as_str(), 0, out);
                }
                out.push('\n');
            }
        }
        for (method_name, method) in &type_def.methods {
            match lang {
                TargetLanguage::Rust => {
                    if let Some(ref desc) = method.description {
                        lang.format_multiline_comment(desc.as_str(), 1, out);
                    }

                    out.push_str(
                        format!("\tpub unsafe fn {}(\n\t\t&self,\n", method_name).as_str(),
                    );

                    for arg in &method.in_args {
                        // Rust does not support per-argument documentation.
                        /*
                        if let Some(ref desc) = arg.description {
                            lang.format_multiline_comment(desc.as_str(), 2, out);
                        }
                        */
                        out.push_str(format!("\t\t{}: ", arg.name).as_str());
                        arg.kind.fmt_write(lang, out);
                        out.push_str(",\n");
                    }

                    out.push_str("\t) -> i64 {\n\t\tself.cap.call(");
                }
                TargetLanguage::C => {
                    if let Some(ref desc) = method.description {
                        lang.format_multiline_comment(desc.as_str(), 0, out);
                    }

                    out.push_str(
                        format!(
                            "static inline int64_t {}_{}(\n\tstruct {} me",
                            type_name, method_name, type_name
                        )
                        .as_str(),
                    );
                    for arg in &method.in_args {
                        out.push_str(",\n");
                        if let Some(ref desc) = arg.description {
                            lang.format_multiline_comment(desc.as_str(), 1, out);
                        }
                        out.push_str("\t");
                        arg.kind.fmt_write(lang, out);
                        out.push_str(format!(" {}", arg.name).as_str());
                    }
                    out.push_str("\n) {\n\treturn cptr_invoke(me.cap");
                }
                TargetLanguage::Markdown => {
                    out.push_str(format!("- `{}`\n\n", method_name).as_str());
                    if let Some(ref desc) = method.description {
                        lang.format_multiline_comment(desc.as_str(), 0, out);
                        out.push('\n');
                    }

                    out.push_str("| Argument | Kind | Description\n");
                    out.push_str("| -------- | ---- | ----------- |\n");
                    for arg in &method.in_args {
                        out.push_str("| ");
                        out.push_str(arg.name.as_str());
                        out.push_str(" | ");
                        arg.kind.fmt_write(lang, out);
                        out.push_str(" | ");
                        if let Some(ref desc) = arg.description {
                            let s: String = desc
                                .chars()
                                .map(|x| if x == '\n' { ' ' } else { x })
                                .collect();
                            out.push_str(s.as_str());
                        }
                        out.push_str(" |\n");
                    }
                    out.push_str("\n");
                }
            }

            let mut invoke_args = method.out_args.clone();
            if invoke_args.len() > N_CAP_INVOKE_ARGUMENTS {
                panic!("generate_types: Too many capability invocation arguments (out_args) for method '{}'. At most {} arguments are supported.", method_name, N_CAP_INVOKE_ARGUMENTS);
            }
            invoke_args.resize(N_CAP_INVOKE_ARGUMENTS, CapInvokeArgument::Constant(0));

            for arg in invoke_args {
                match lang {
                    TargetLanguage::Rust => {
                        arg.fmt_write(lang, &method.in_args, out);
                        out.push_str(", ");
                    }
                    TargetLanguage::C => {
                        out.push_str(", ");
                        arg.fmt_write(lang, &method.in_args, out);
                    }
                    TargetLanguage::Markdown => {}
                }
            }

            match lang {
                TargetLanguage::Rust => {
                    out.push_str(")\n\t}\n\n");
                }
                TargetLanguage::C => {
                    out.push_str(");\n}\n\n");
                }
                TargetLanguage::Markdown => {}
            }
        }
        match lang {
            TargetLanguage::Rust => {
                out.push_str("}\n\n");
            }
            TargetLanguage::C => {}
            TargetLanguage::Markdown => {}
        }
    }
}
