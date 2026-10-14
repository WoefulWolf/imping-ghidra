# imping-ghidra

Ghidra exporter for the imping modding suite. `ImpingExport.java` writes the current program as an imping IR file (JSON): its build identity, every function and global with a non-default name, and the types they use. `imping-codegen` turns that file into Rust bindings.

Status: early development, not published. Supports x86 and x64 PE programs; tested with Ghidra 12.1.2.

## What is exported

- **Functions:** every function in the program whose name is not a Ghidra default (`FUN_…`), except the exception-handling funclets Ghidra's analysis names (`Unwind@…`, `Catch@…`), which are compiler-generated pieces of other functions. Its Ghidra function tags are kept, and its first bytes (up to 16, stopping before any byte the loader relocates) are recorded so a hook can check it is patching the expected code.
- **Globals:** every data label whose name is not a Ghidra default (`DAT_…`, `PTR_…`, `s_…`).
- **Types:** only those used by the exported functions and globals, directly or through other types.
- **Identity:** the module's file name, image base, timestamp and image size from its PE header, and its SHA-256 when Ghidra recorded one.

Name the functions and globals you want before exporting; a namespace or class in Ghidra becomes a namespace in the IR.

## Usage

In Ghidra: open the Script Manager, add this repository's `ghidra_scripts` folder to the script directories, then run `ImpingExport.java` from the `imping` category. It asks where to save the IR file.

Headless, with the program already imported and analysed:

```powershell
& "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat" <project dir> <project name> `
    -process game.exe -noanalysis `
    -scriptPath <imping-ghidra>\ghidra_scripts `
    -postScript ImpingExport.java out\game.ir.json
```

Then check the file, or point a mod's `build.rs` at it:

```powershell
imping check out\game.ir.json
```

## Development

The checks need a Ghidra installation; set `GHIDRA_INSTALL_DIR` to it (the folder containing `support\analyzeHeadless.bat`). They compile the script against Ghidra's libraries, then run an end-to-end test: build the small Rust program in `tests/fixture`, analyse and export it with Ghidra's headless analyzer, check the IR against the program's own headers and bytes, and compile bindings generated from it against `imping-runtime`. The test depends on the sibling `imping-ir`, `imping-codegen` and `imping-runtime` repositories by relative path.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
