//! Builds the fixture program, exports it with Ghidra's headless analyzer and
//! `ImpingExport.java`, checks the IR against the program itself, then
//! generates bindings from the IR and compiles them against imping-runtime.
//!
//! Needs `GHIDRA_INSTALL_DIR` to point at a Ghidra installation. Takes a few
//! minutes: Ghidra analyses the whole program, including its standard library.

use imping_ir::{Architecture, Function, Ir, Module, Primitive, TypeDef, TypeId, TypeKind};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The imping-ghidra repository root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tests/e2e is two levels below the repo root")
        .to_owned()
}

/// A fresh scratch directory.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Runs a command, panicking with its output if it fails.
fn run(command: &mut Command, what: &str) {
    let output = command.output().unwrap_or_else(|e| panic!("{what}: {e}"));
    if !output.status.success() {
        panic!(
            "{what} failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// The parts of a PE file the test checks the IR against.
struct Pe {
    bytes: Vec<u8>,
    image_base: u64,
    timestamp: u32,
    image_size: u32,
    /// (virtual address, virtual size, file offset, file size) per section.
    sections: Vec<(u32, u32, u32, u32)>,
}

impl Pe {
    fn read(path: &Path) -> Self {
        let bytes = std::fs::read(path).expect("read the fixture executable");
        let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let u32_at =
            |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let u64_at =
            |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let nt = u32_at(0x3c) as usize;
        let sections_count = u16_at(nt + 6) as usize;
        let optional = nt + 24;
        let optional_size = u16_at(nt + 20) as usize;
        let image_base = if u16_at(optional) == 0x20b {
            u64_at(optional + 24)
        } else {
            u64::from(u32_at(optional + 28))
        };
        let sections = (0..sections_count)
            .map(|i| {
                let header = optional + optional_size + i * 40;
                (
                    u32_at(header + 12),
                    u32_at(header + 8),
                    u32_at(header + 20),
                    u32_at(header + 16),
                )
            })
            .collect();
        Self {
            timestamp: u32_at(nt + 8),
            image_size: u32_at(optional + 56),
            image_base,
            sections,
            bytes,
        }
    }

    /// The file bytes at an RVA.
    fn at(&self, rva: u32, len: usize) -> &[u8] {
        let (va, _, raw, _) = self
            .sections
            .iter()
            .copied()
            .find(|&(va, size, _, raw_size)| rva >= va && rva < va + size.max(raw_size))
            .unwrap_or_else(|| panic!("RVA {rva:#x} is in no section"));
        let offset = (raw + (rva - va)) as usize;
        &self.bytes[offset..offset + len]
    }
}

fn type_def(module: &Module, id: TypeId) -> &TypeDef {
    module
        .types
        .iter()
        .find(|def| def.id == id)
        .unwrap_or_else(|| panic!("type id {} is defined", id.0))
}

/// A type through typedefs.
fn peel(module: &Module, mut id: TypeId) -> &TypeDef {
    loop {
        let def = type_def(module, id);
        match def.kind {
            TypeKind::Typedef { target } => id = target,
            _ => return def,
        }
    }
}

fn is_primitive(module: &Module, id: TypeId, primitive: Primitive) -> bool {
    matches!(peel(module, id).kind, TypeKind::Primitive { primitive: p } if p == primitive)
}

/// The struct a pointer type points to.
fn pointee_struct(module: &Module, id: TypeId) -> &TypeDef {
    let TypeKind::Pointer { pointee, .. } = peel(module, id).kind else {
        panic!("type {} is not a pointer", type_def(module, id).name);
    };
    let def = peel(module, pointee);
    assert!(
        matches!(def.kind, TypeKind::Struct { .. }),
        "{} is not a struct",
        def.name
    );
    def
}

/// The (name, type) fields of a struct.
fn fields(def: &TypeDef) -> Vec<(&str, TypeId, u64)> {
    let TypeKind::Struct { fields, .. } = &def.kind else {
        panic!("{} is not a struct", def.name);
    };
    fields
        .iter()
        .map(|field| (field.name.as_str(), field.type_id, field.offset))
        .collect()
}

fn function<'a>(module: &'a Module, name: &str) -> &'a Function {
    module
        .functions
        .iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("function {name} was exported"))
}

#[test]
fn exports_the_fixture_program() {
    let ghidra = PathBuf::from(
        std::env::var_os("GHIDRA_INSTALL_DIR")
            .expect("set GHIDRA_INSTALL_DIR to a Ghidra installation"),
    );
    let root = repo_root();

    // 1. Build the fixture program, with its program database.
    let fixture_target = scratch("fixture-target");
    run(
        Command::new(env!("CARGO"))
            .args(["build", "-p", "fixture", "--target-dir"])
            .arg(&fixture_target)
            .current_dir(&root),
        "building the fixture",
    );
    let exe = fixture_target.join("debug").join("fixture.exe");

    // 2. Analyse it headless and export it.
    let project = scratch("ghidra-project");
    let ir_path = project.join("fixture.ir.json");
    run(
        Command::new(ghidra.join("support").join("analyzeHeadless.bat"))
            .arg(&project)
            .arg("imping-e2e")
            .arg("-import")
            .arg(&exe)
            .arg("-overwrite")
            .arg("-scriptPath")
            .arg(root.join("ghidra_scripts"))
            .arg("-postScript")
            .arg("ImpingExport.java")
            .arg(&ir_path)
            .arg("-deleteProject"),
        "Ghidra's headless analyzer",
    );

    // 3. Check the IR against the program.
    let text = std::fs::read_to_string(&ir_path).expect("the exporter wrote the IR");
    let ir = Ir::from_json_str(&text).expect("the IR parses");
    ir.validate().expect("the IR is valid");
    assert_eq!(ir.modules.len(), 1);
    let module = &ir.modules[0];
    let pe = Pe::read(&exe);
    assert_eq!(module.name, "fixture.exe");
    assert_eq!(module.architecture, Architecture::X64);
    assert_eq!(module.image_base, pe.image_base);
    assert_eq!(module.timestamp, pe.timestamp);
    assert_eq!(module.image_size, pe.image_size);
    println!(
        "exported {} functions, {} globals and {} types",
        module.functions.len(),
        module.globals.len(),
        module.types.len()
    );

    assert!(
        module.functions.iter().all(|f| !f.name.starts_with("FUN_")),
        "functions with default names are not exported"
    );
    let funclet = |name: &str| {
        ["Unwind@", "Catch@", "Catch_All@"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    };
    assert!(
        module.functions.iter().all(|f| !funclet(&f.name)),
        "exception-handling funclets are not exported"
    );
    assert!(
        module.globals.iter().all(|g| !g.name.starts_with("DAT_")),
        "globals with default names are not exported"
    );

    // The program database places a crate's items in a namespace named after it.
    let add = function(module, "fixture_add");
    assert_eq!(add.namespace, ["fixture"]);
    assert_eq!(add.parameters.len(), 2);
    for parameter in &add.parameters {
        assert!(is_primitive(module, parameter.type_id, Primitive::I32));
    }
    assert!(is_primitive(module, add.return_type, Primitive::I32));
    assert!(
        !add.verification.is_empty(),
        "fixture_add has verification bytes"
    );
    assert_eq!(
        add.verification,
        pe.at(add.rva, add.verification.len()),
        "the RVA and verification bytes match the executable"
    );

    let damage = function(module, "fixture_damage");
    assert_eq!(damage.parameters.len(), 2);
    let entity = pointee_struct(module, damage.parameters[0].type_id);
    assert!(entity.name.ends_with("Entity"), "{}", entity.name);
    assert!(is_primitive(
        module,
        damage.parameters[1].type_id,
        Primitive::F32
    ));
    let entity_fields = fields(entity);
    let names: Vec<&str> = entity_fields.iter().map(|(name, ..)| *name).collect();
    assert_eq!(names, ["kind", "position", "health"]);
    let (_, position, position_offset) = entity_fields[1];
    assert_eq!(position_offset, 4);
    let vector = peel(module, position);
    assert!(vector.name.ends_with("Vector3"), "{}", vector.name);
    let vector_fields = fields(vector);
    assert_eq!(
        vector_fields
            .iter()
            .map(|(name, ..)| *name)
            .collect::<Vec<_>>(),
        ["x", "y", "z"]
    );
    assert!(
        vector_fields
            .iter()
            .all(|&(_, ty, _)| is_primitive(module, ty, Primitive::F32))
    );

    let length = function(module, "fixture_length");
    assert!(is_primitive(module, length.return_type, Primitive::F32));
    assert!(
        pointee_struct(module, length.parameters[0].type_id)
            .name
            .ends_with("Vector3")
    );

    let gravity = module
        .globals
        .iter()
        .find(|global| global.name == "fixture_gravity")
        .expect("fixture_gravity was exported");
    assert!(is_primitive(module, gravity.type_id, Primitive::F32));
    assert_eq!(pe.at(gravity.rva, 4), 9.81f32.to_le_bytes());

    // 4. Generate bindings and compile them against imping-runtime.
    let bindings = imping_codegen::Generator::new()
        .generate(&ir)
        .expect("bindings generate");
    println!("codegen warnings: {}", bindings.warnings().len());
    let source = bindings.source();
    assert!(source.contains("pub unsafe fn fixture_add("));
    assert!(source.contains("pub static fixture_gravity:"));

    let crate_dir = scratch("bindings-check");
    let runtime = root.join("..").join("imping-runtime");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"bindings-check\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n\
             [dependencies]\nimping-runtime = {{ path = {:?} }}\n\n[workspace]\n",
            runtime.display().to_string().replace('\\', "/")
        ),
    )
    .unwrap();
    std::fs::write(crate_dir.join("src").join("imped.rs"), source).unwrap();
    std::fs::write(
        crate_dir.join("src").join("lib.rs"),
        "//! Bindings generated from the fixture program.\n\ninclude!(\"imped.rs\");\n",
    )
    .unwrap();
    run(
        Command::new(env!("CARGO"))
            .args(["check", "--quiet"])
            .env("RUSTFLAGS", "-D warnings")
            .current_dir(&crate_dir),
        "compiling the generated bindings",
    );
}
