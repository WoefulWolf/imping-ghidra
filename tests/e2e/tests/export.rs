//! Exports the fixture program with `ImpingExport.java` in headless Ghidra, once,
//! and checks the IR against the executable.
//!
//! Needs `GHIDRA_INSTALL_DIR` set to a Ghidra installation. Takes a few minutes,
//! since Ghidra analyses the whole program including its standard library.

use imping_ir::{Architecture, Function, Ir, Module, Primitive, TypeDef, TypeId, TypeKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Returns the imping-ghidra repository root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tests/e2e is two levels below the repo root")
        .to_owned()
}

/// Returns an empty scratch directory, clearing out any previous run's.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Runs a command, returning its output as the error if it fails.
fn run(command: &mut Command, what: &str) -> Result<(), String> {
    let output = command.output().map_err(|e| format!("{what}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{what} failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// The parts of a PE file the tests check the IR against.
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

    /// Returns the file bytes at an RVA.
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

/// Builds the fixture, exports it with Ghidra and checks the IR is valid.
fn build_and_export() -> Result<(Ir, Pe), String> {
    let ghidra = PathBuf::from(
        std::env::var_os("GHIDRA_INSTALL_DIR")
            .ok_or("set GHIDRA_INSTALL_DIR to a Ghidra installation")?,
    );
    let root = repo_root();

    // A debug build, so Ghidra gets the PDB with names and types.
    let fixture_target = scratch("fixture-target");
    run(
        Command::new(env!("CARGO"))
            .args(["build", "-p", "fixture", "--target-dir"])
            .arg(&fixture_target)
            .current_dir(&root),
        "building the fixture",
    )?;
    let exe = fixture_target.join("debug").join("fixture.exe");

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
    )?;

    let text = std::fs::read_to_string(&ir_path).map_err(|e| format!("reading the IR: {e}"))?;
    let ir = Ir::from_json_str(&text).map_err(|e| format!("parsing the IR: {e}"))?;
    ir.validate()
        .map_err(|e| format!("the IR is invalid: {e}"))?;
    Ok((ir, Pe::read(&exe)))
}

/// Returns the exported IR's module and the executable, exporting on first use.
fn exported() -> (&'static Module, &'static Pe) {
    static EXPORT: OnceLock<Result<(Ir, Pe), String>> = OnceLock::new();
    match EXPORT.get_or_init(build_and_export) {
        Ok((ir, pe)) => {
            assert_eq!(ir.modules.len(), 1);
            (&ir.modules[0], pe)
        }
        Err(e) => panic!("{e}"),
    }
}

fn type_def(module: &Module, id: TypeId) -> &TypeDef {
    module
        .types
        .iter()
        .find(|def| def.id == id)
        .unwrap_or_else(|| panic!("type id {} is defined", id.0))
}

/// Resolves a type through typedefs.
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

/// Returns the struct a pointer type points to.
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

/// Returns a struct's fields as (name, type, offset).
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
fn identity_matches_the_pe_header() {
    let (module, pe) = exported();
    assert_eq!(module.name, "fixture.exe");
    assert_eq!(module.architecture, Architecture::X64);
    assert_eq!(module.image_base, pe.image_base);
    assert_eq!(module.timestamp, pe.timestamp);
    assert_eq!(module.image_size, pe.image_size);
}

#[test]
fn skips_generated_names() {
    let (module, _) = exported();
    let funclet = |name: &str| {
        ["Unwind@", "Catch@", "Catch_All@"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    };
    let generated = |name: &str| {
        name.starts_with("switchdataD_") || name.starts_with("RTTI_") || name == "vftable_meta_ptr"
    };
    for f in &module.functions {
        assert!(
            !f.name.starts_with("FUN_") && !funclet(&f.name),
            "{}",
            f.name
        );
    }
    for g in &module.globals {
        assert!(
            !g.name.starts_with("DAT_") && !generated(&g.name),
            "{}",
            g.name
        );
    }
}

#[test]
fn exports_function_signatures() {
    let (module, pe) = exported();
    // The program database puts a crate's items in a namespace named after it.
    let add = function(module, "fixture_add");
    assert_eq!(add.namespace, ["fixture"]);
    assert_eq!(add.parameters.len(), 2);
    for parameter in &add.parameters {
        assert!(is_primitive(module, parameter.type_id, Primitive::I32));
    }
    assert!(is_primitive(module, add.return_type, Primitive::I32));
    assert!(!add.verification.is_empty());
    assert_eq!(
        add.verification,
        pe.at(add.rva, add.verification.len()),
        "the RVA and verification bytes match the executable"
    );

    let length = function(module, "fixture_length");
    assert!(is_primitive(module, length.return_type, Primitive::F32));
    let vector = pointee_struct(module, length.parameters[0].type_id);
    assert!(vector.name.ends_with("Vector3"), "{}", vector.name);
}

#[test]
fn exports_struct_layouts() {
    let (module, _) = exported();
    let damage = function(module, "fixture_damage");
    assert_eq!(damage.parameters.len(), 2);
    assert!(is_primitive(
        module,
        damage.parameters[1].type_id,
        Primitive::F32
    ));

    let entity = pointee_struct(module, damage.parameters[0].type_id);
    assert!(entity.name.ends_with("Entity"), "{}", entity.name);
    let entity_fields = fields(entity);
    let names: Vec<&str> = entity_fields.iter().map(|(name, ..)| *name).collect();
    assert_eq!(names, ["kind", "position", "health"]);
    let (_, position, position_offset) = entity_fields[1];
    assert_eq!(position_offset, 4);

    let vector = peel(module, position);
    assert!(vector.name.ends_with("Vector3"), "{}", vector.name);
    let vector_fields = fields(vector);
    let names: Vec<&str> = vector_fields.iter().map(|(name, ..)| *name).collect();
    assert_eq!(names, ["x", "y", "z"]);
    for &(_, ty, _) in &vector_fields {
        assert!(is_primitive(module, ty, Primitive::F32));
    }
}

#[test]
fn exports_globals() {
    let (module, pe) = exported();
    let gravity = module
        .globals
        .iter()
        .find(|global| global.name == "fixture_gravity")
        .expect("fixture_gravity was exported");
    assert!(is_primitive(module, gravity.type_id, Primitive::F32));
    assert_eq!(pe.at(gravity.rva, 4), 9.81f32.to_le_bytes());
}
