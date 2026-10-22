# imping-ghidra

A Ghidra script that exports a program as an imping IR file: its build identity, every function and global you've named, and the types they use. [imping-codegen](https://github.com/WoefulWolf/imping-codegen) turns that file into Rust bindings.

## Usage

In Ghidra's Script Manager, add this repository's `ghidra_scripts` folder, then run `ImpingExport.java` from the `imping` category. It asks where to save the file.

Headless, with the program already analysed:

```powershell
analyzeHeadless.bat <project dir> <project name> -process target.exe -noanalysis `
    -scriptPath <imping-ghidra>\ghidra_scripts -postScript ImpingExport.java target.ir.json
```

## What gets exported

- **Functions and globals** with a name you or the program's symbols gave them. Ghidra's defaults (`FUN_…`, `DAT_…`) and names its analysis generates (exception funclets, switch tables, RTTI metadata) are skipped.
- **Types** those functions and globals use.
- **Namespaces** from Ghidra's namespaces and classes, and from `::` in type names (`Hw::cVec4`).
- **Base classes:** a struct's field at offset 0 is marked as its base when the program's MSVC RTTI says so (x64), or else when it's named `base`. Where RTTI disagrees with a field named `base`, the export prints a warning saying why.
- **Safe calls:** tag a function `imping-safe` when it's always fine to call with valid arguments and keeps none of its pointer arguments. Its binding then needs no `unsafe`.
- **Verification bytes:** up to 16 of each function's first bytes, so hooks can check they patch the code they expect.

Early development. Supports x86 and x64 PE programs; tested with Ghidra 12.1.2.

If imping helped your project, a mention or link back is appreciated. I'd also love to see what you make with it: share it in [Show and tell](https://github.com/WoefulWolf/imping/discussions/categories/show-and-tell), and it might get featured here!

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

AI assistance was used for parts of this project.
