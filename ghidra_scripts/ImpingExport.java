// Exports the current program as an imping IR file (JSON): its build identity,
// every function and global with a non-default name, and the types they use.
//
// Exported functions are the non-external functions whose names are not Ghidra
// defaults (not FUN_...), except the exception-handling funclets Ghidra's
// analysis names (Unwind@..., Catch@...). Exported globals are the data
// labels a user or a symbol source named: not defaults (DAT_..., PTR_...,
// s_...), not names Ghidra's analysis generated (switchdataD_...), and not
// RTTI metadata (RTTI_..., vftable_meta_ptr); vftable labels are kept. Types
// are exported only when an exported function or global uses them, directly
// or through other types.
//
// A struct's field at offset 0 is marked as its base class from the program's
// MSVC RTTI (x64) when RTTI describes a class of exactly the struct's name: the
// field is the base when its type is the class's first base, or another base
// RTTI places at offset 0 (template names compare without their arguments).
// Where RTTI contradicts a field named `base`, the field is not marked and a
// warning says why. A struct RTTI does not describe falls back to its name: a
// struct field at offset 0 named `base` is the base.
//
// In the GUI, the script asks where to save the file. Headless, pass the output
// path as the script's argument:
//
//   analyzeHeadless <project dir> <project> -process <program> -noanalysis
//       -scriptPath <imping-ghidra>/ghidra_scripts
//       -postScript ImpingExport.java <output.ir.json>
//
// Only x86 and x64 PE programs are supported.
//@category imping

import com.google.gson.stream.JsonWriter;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.data.WideChar32DataType;
import ghidra.program.model.data.WideCharDataType;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

public class ImpingExport extends GhidraScript {

    /** The IR format version this script writes. */
    private static final int FORMAT_MAJOR = 1;
    private static final int FORMAT_MINOR = 1;

    /** The most bytes recorded to verify a function's start before hooking it. */
    private static final int VERIFICATION_BYTES = 16;

    /** Names Ghidra's analysis gives exception-handling funclets. */
    private static final Pattern EXCEPTION_FUNCLET =
        Pattern.compile("(Unwind|Catch|Catch_All)@[0-9a-fA-F]+");

    /** Labels Ghidra's class recovery gives RTTI metadata. */
    private static final Pattern RTTI_METADATA = Pattern.compile("RTTI_.*|vftable_meta_ptr");

    @Override
    protected void run() throws Exception {
        File output = outputFile();
        if (output == null) {
            return;
        }
        Exporter exporter = new Exporter(currentProgram);
        exporter.collect();
        try (Writer writer = Files.newBufferedWriter(output.toPath(), StandardCharsets.UTF_8);
                JsonWriter json = new JsonWriter(writer)) {
            json.setIndent("  ");
            exporter.write(json);
        }
        for (String warning : exporter.warnings) {
            println("imping: warning: " + warning);
        }
        println(String.format("imping: exported %d functions, %d globals and %d types to %s",
            exporter.functions.size(), exporter.globals.size(), exporter.types.size(), output));
    }

    /** The output file: the script argument when headless, otherwise asked for. */
    private File outputFile() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0) {
            return new File(args[0]);
        }
        if (isRunningHeadless()) {
            throw new IllegalArgumentException(
                "imping: pass the output file as the script's argument");
        }
        return askFile("Export imping IR (" + currentProgram.getName() + ".ir.json)", "Export");
    }

    /** One global: its symbol and data. */
    private record GlobalItem(Symbol symbol, Data data) {}

    /** A type in the IR's type table: its namespace path and name. */
    private record TypeEntry(int id, List<String> namespace, String name, TypeBody body) {}

    /** Writes the kind-specific part of a type entry. */
    @FunctionalInterface
    private interface TypeBody {
        void write(JsonWriter json) throws IOException;
    }

    /** One base class RTTI lists for a class: its name and offset in the class. */
    private record RttiBase(String name, int offset, boolean isVirtual) {}

    /** One field of a struct or union, resolved to type ids. */
    private record FieldEntry(String name, int type, long offset, int bitOffset, int bitWidth,
            boolean base) {
        boolean isBitField() {
            return bitWidth > 0;
        }
    }

    /** Collects what to export from a program and writes it as IR. */
    private final class Exporter {
        private final Program program;
        private final Memory memory;
        private final Listing listing;
        private final Address imageBase;
        private final boolean x64;

        final List<Function> functions = new ArrayList<>();
        final List<GlobalItem> globals = new ArrayList<>();
        final List<TypeEntry> types = new ArrayList<>();
        /** Contradictions found while exporting, for the user to check. */
        final List<String> warnings = new ArrayList<>();
        private final Map<String, Integer> typeIds = new HashMap<>();
        /** RTTI's base classes by class name (see {@link #normalize}), read on first use. */
        private Map<String, List<RttiBase>> rttiClasses;

        Exporter(Program program) {
            this.program = program;
            this.memory = program.getMemory();
            this.listing = program.getListing();
            this.imageBase = program.getImageBase();
            String format = program.getExecutableFormat();
            if (format == null || !format.contains("Portable Executable")) {
                throw new IllegalStateException(
                    "imping: only PE programs are supported, not " + format);
            }
            if (!program.getLanguage().getProcessor().toString().equals("x86")) {
                throw new IllegalStateException("imping: only x86 and x64 programs are supported, not "
                    + program.getLanguage().getProcessor());
            }
            this.x64 = program.getDefaultPointerSize() == 8;
        }

        void collect() throws Exception {
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (!function.isExternal()
                        && function.getSymbol().getSource() != SourceType.DEFAULT
                        && !isExceptionFunclet(function)
                        && isLoaded(function.getEntryPoint())
                        && rva(function.getEntryPoint()) >= 0) {
                    functions.add(function);
                }
            }
            SymbolIterator symbols = program.getSymbolTable().getAllSymbols(false);
            while (symbols.hasNext()) {
                monitor.checkCancelled();
                Symbol symbol = symbols.next();
                Address address = symbol.getAddress();
                if (symbol.getSymbolType() != SymbolType.LABEL
                        || symbol.isExternal()
                        || symbol.getSource() == SourceType.DEFAULT
                        || isGeneratedDataLabel(symbol)
                        || !symbol.isPrimary()
                        || !address.isMemoryAddress()
                        || !isLoaded(address)
                        || rva(address) < 0
                        || listing.getInstructionContaining(address) != null) {
                    continue;
                }
                Data data = listing.getDataAt(address);
                if (data != null) {
                    globals.add(new GlobalItem(symbol, data));
                }
            }
            globals.sort((a, b) -> a.symbol().getAddress().compareTo(b.symbol().getAddress()));
            // Assign type ids in a deterministic order: functions, then globals.
            for (Function function : functions) {
                typeId(function.getReturnType());
                for (Parameter parameter : parameters(function)) {
                    typeId(parameter.getDataType());
                }
            }
            for (GlobalItem global : globals) {
                globalType(global.data());
            }
        }

        // ---------------------------------------------------------------- output

        void write(JsonWriter json) throws Exception {
            json.beginObject();
            json.name("format_version").beginObject();
            json.name("major").value(FORMAT_MAJOR);
            json.name("minor").value(FORMAT_MINOR);
            json.endObject();
            json.name("modules").beginArray();
            writeModule(json);
            json.endArray();
            json.endObject();
        }

        private void writeModule(JsonWriter json) throws Exception {
            json.beginObject();
            json.name("name").value(moduleName());
            json.name("architecture").value(x64 ? "x64" : "x86");
            json.name("image_base").value(hex(imageBase.getOffset()));
            Address nt = ntHeaders();
            json.name("timestamp").value(hex(Integer.toUnsignedLong(memory.getInt(nt.add(8)))));
            json.name("image_size").value(hex(Integer.toUnsignedLong(memory.getInt(nt.add(24 + 56)))));
            String sha256 = program.getExecutableSHA256();
            if (sha256 != null && !sha256.isEmpty()) {
                json.name("hash").beginObject();
                json.name("algorithm").value("sha256");
                json.name("value").value(sha256.toLowerCase());
                json.endObject();
            }

            json.name("types").beginArray();
            for (TypeEntry entry : types) {
                json.beginObject();
                json.name("id").value(entry.id());
                json.name("name").value(entry.name());
                if (!entry.namespace().isEmpty()) {
                    json.name("namespace").beginArray();
                    for (String segment : entry.namespace()) {
                        json.value(segment);
                    }
                    json.endArray();
                }
                entry.body().write(json);
                json.endObject();
            }
            json.endArray();

            json.name("functions").beginArray();
            for (Function function : functions) {
                monitor.checkCancelled();
                writeFunction(json, function);
            }
            json.endArray();

            json.name("globals").beginArray();
            for (GlobalItem global : globals) {
                json.beginObject();
                json.name("name").value(global.symbol().getName());
                writeNamespace(json, global.symbol().getParentNamespace());
                json.name("rva").value(hex(rva(global.symbol().getAddress())));
                json.name("type").value(globalType(global.data()));
                json.endObject();
            }
            json.endArray();
            json.endObject();
        }

        private void writeFunction(JsonWriter json, Function function) throws IOException {
            json.beginObject();
            json.name("name").value(function.getName());
            writeNamespace(json, function.getParentNamespace());
            json.name("rva").value(hex(rva(function.getEntryPoint())));
            json.name("calling_convention").value(convention(function.getCallingConventionName()));
            json.name("return_type").value(typeId(function.getReturnType()));
            boolean custom = function.hasCustomVariableStorage();
            json.name("parameters").beginArray();
            for (Parameter parameter : parameters(function)) {
                json.beginObject();
                json.name("name").value(parameter.getName());
                json.name("type").value(typeId(parameter.getDataType()));
                json.name("storage");
                if (!writeStorage(json, parameter.getVariableStorage())) {
                    custom = true;
                }
                json.endObject();
            }
            json.endArray();
            json.name("variadic").value(function.hasVarArgs());
            json.name("custom_storage").value(custom);
            List<String> tags = new ArrayList<>();
            for (FunctionTag tag : function.getTags()) {
                tags.add(tag.getName());
            }
            if (!tags.isEmpty()) {
                Collections.sort(tags);
                json.name("tags").beginArray();
                for (String tag : tags) {
                    json.value(tag);
                }
                json.endArray();
            }
            String verification = verification(function);
            if (!verification.isEmpty()) {
                json.name("verification").value(verification);
            }
            json.endObject();
        }

        /**
         * Writes a parameter's storage. Returns false if it is not a single
         * register or stack slot, so the function needs custom storage.
         */
        private boolean writeStorage(JsonWriter json, VariableStorage storage) throws IOException {
            json.beginObject();
            if (storage.isRegisterStorage()) {
                json.name("kind").value("register");
                json.name("value").value(registerName(storage.getRegister().getName()));
                json.endObject();
                return true;
            }
            if (storage.isStackStorage()) {
                json.name("kind").value("stack");
                json.name("offset").value(storage.getStackOffset());
                json.endObject();
                return true;
            }
            Varnode[] varnodes = storage.getVarnodes();
            if (varnodes.length > 0 && varnodes[0].isRegister()) {
                json.name("kind").value("register");
                json.name("value").value(
                    registerName(program.getRegister(varnodes[0]).getName()));
            } else if (varnodes.length > 0 && varnodes[0].getAddress().isStackAddress()) {
                json.name("kind").value("stack");
                json.name("offset").value(varnodes[0].getOffset());
            } else {
                json.name("kind").value("stack");
                json.name("offset").value(0);
            }
            json.endObject();
            return false;
        }

        /**
         * Splits a C++ name at its top-level `::` into namespace segments and the
         * name: `Hw::cVec4` is `[Hw, cVec4]`, and `lib::Array<hap::Token>` is
         * `[lib, Array<hap::Token>]`, since template arguments (and parameter
         * lists inside them) are kept whole. A name without `::` is one segment.
         */
        private static List<String> splitPath(String name) {
            List<String> segments = new ArrayList<>();
            int depth = 0;
            int start = 0;
            for (int i = 0; i < name.length(); i++) {
                char c = name.charAt(i);
                if (c == '<' || c == '(') {
                    depth++;
                } else if ((c == '>' || c == ')') && depth > 0) {
                    depth--;
                } else if (depth == 0 && c == ':' && i + 1 < name.length() && name.charAt(i + 1) == ':') {
                    if (i > start) {
                        segments.add(name.substring(start, i));
                    }
                    start = i + 2;
                    i++;
                }
            }
            if (start < name.length() || segments.isEmpty()) {
                segments.add(name.substring(start));
            }
            return segments;
        }

        private void writeNamespace(JsonWriter json, Namespace namespace) throws IOException {
            List<String> path = new ArrayList<>();
            for (Namespace current = namespace; current != null && !current.isGlobal();
                    current = current.getParentNamespace()) {
                path.add(current.getName());
            }
            if (path.isEmpty()) {
                return;
            }
            Collections.reverse(path);
            json.name("namespace").beginArray();
            for (String segment : path) {
                json.value(segment);
            }
            json.endArray();
        }

        // ----------------------------------------------------------- identity

        /** The module's file name, as the process loads it. */
        private String moduleName() {
            String path = program.getExecutablePath();
            if (path != null && !path.isEmpty()) {
                String name = new File(path).getName();
                if (!name.isEmpty()) {
                    return name;
                }
            }
            return program.getName();
        }

        /** The address of the PE NT headers, which Ghidra maps at the image base. */
        private Address ntHeaders() throws MemoryAccessException {
            if (memory.getShort(imageBase) != 0x5a4d) {
                throw new IllegalStateException(
                    "imping: no PE headers at the image base; re-import with headers loaded");
            }
            Address nt = imageBase.add(Integer.toUnsignedLong(memory.getInt(imageBase.add(0x3c))));
            if (memory.getInt(nt) != 0x00004550) {
                throw new IllegalStateException("imping: invalid PE signature at " + nt);
            }
            return nt;
        }

        // ---------------------------------------------------------- functions

        /**
         * Whether a function is an exception-handling funclet that Ghidra's
         * analysis named (Unwind@..., Catch@..., Catch_All@...). Such names are
         * not defaults, but the funclets are compiler-generated pieces of other
         * functions, not functions to call or hook. A name a user chose is kept.
         */
        private boolean isExceptionFunclet(Function function) {
            return function.getSymbol().getSource() == SourceType.ANALYSIS
                && EXCEPTION_FUNCLET.matcher(function.getName()).matches();
        }

        /**
         * Whether a data label was generated rather than chosen: any label
         * Ghidra's analysis named (switch tables such as switchdataD_...,
         * thread-block fields), and the RTTI metadata labels its class
         * recovery creates (RTTI_... descriptors, vftable_meta_ptr). Labels of
         * virtual function tables (vftable) are kept.
         */
        private boolean isGeneratedDataLabel(Symbol symbol) {
            return symbol.getSource() == SourceType.ANALYSIS
                || RTTI_METADATA.matcher(symbol.getName()).matches();
        }

        /** A function's parameters, without a hidden return-storage pointer. */
        private List<Parameter> parameters(Function function) {
            List<Parameter> parameters = new ArrayList<>();
            for (Parameter parameter : function.getParameters()) {
                if (parameter.getAutoParameterType() != AutoParameterType.RETURN_STORAGE_PTR) {
                    parameters.add(parameter);
                }
            }
            return parameters;
        }

        /** Maps a Ghidra calling convention name to an IR one. */
        private String convention(String name) {
            if (x64) {
                return "win64";
            }
            if (name == null) {
                return "cdecl";
            }
            switch (name) {
                case "__stdcall":
                    return "stdcall";
                case "__fastcall":
                    return "fastcall";
                case "__thiscall":
                    return "thiscall";
                default:
                    return "cdecl";
            }
        }

        /** A register name in lowercase, without Ghidra's sub-register suffix (XMM1_Qa). */
        private String registerName(String name) {
            String lower = name.toLowerCase();
            if (lower.startsWith("xmm") || lower.startsWith("ymm")) {
                int underscore = lower.indexOf('_');
                if (underscore > 0) {
                    return lower.substring(0, underscore);
                }
            }
            return lower;
        }

        /**
         * The first bytes of a function as hex, stopping at the end of its first
         * address range and at the first byte the loader relocates.
         */
        private String verification(Function function) {
            Address entry = function.getEntryPoint();
            long length = VERIFICATION_BYTES;
            AddressRange range = function.getBody().getRangeContaining(entry);
            if (range != null) {
                length = Math.min(length, range.getMaxAddress().subtract(entry) + 1);
            }
            if (length <= 0) {
                return "";
            }
            Iterator<Relocation> relocations = program.getRelocationTable()
                .getRelocations(new AddressSet(entry, entry.add(length - 1)));
            while (relocations.hasNext()) {
                Relocation relocation = relocations.next();
                length = Math.min(length, Math.max(0, relocation.getAddress().subtract(entry)));
            }
            byte[] bytes = new byte[(int) length];
            int read;
            try {
                read = memory.getBytes(entry, bytes);
            } catch (MemoryAccessException e) {
                return "";
            }
            StringBuilder hex = new StringBuilder(read * 2);
            for (int i = 0; i < read; i++) {
                hex.append(String.format("%02x", bytes[i] & 0xff));
            }
            return hex.toString();
        }

        // -------------------------------------------------------------- types

        /** The type id for a global's data, sizing variable-length data such as strings. */
        private int globalType(Data data) {
            DataType type = data.getDataType();
            if (type.getLength() > 0 || data.getLength() <= 0) {
                return typeId(type);
            }
            // A variable-length type, such as a string: an array of its
            // characters, using Ghidra's character types so the array is
            // recognised as text.
            String name = type.getName().toLowerCase();
            DataType element = name.contains("unicode32") ? WideChar32DataType.dataType
                : name.contains("unicode") ? WideChar16DataType.dataType
                : CharDataType.dataType;
            int elementSize = Math.max(element.getLength(), 1);
            int elementId = typeId(element);
            int count = data.getLength() / elementSize;
            String key = "imping:array:" + element.getName() + ":" + count;
            return synthetic(key, element.getName() + "[" + count + "]", json -> {
                json.name("kind").value("array");
                json.name("element").value(elementId);
                json.name("count").value(count);
            });
        }

        /** The id of a Ghidra data type, adding it (and the types it uses) on first use. */
        int typeId(DataType type) {
            if (type == null) {
                type = VoidDataType.dataType;
            }
            String key = type.getPathName();
            Integer existing = typeIds.get(key);
            if (existing != null) {
                return existing;
            }
            int id = reserve(key);
            List<String> path = isNamedItem(type) ? splitPath(type.getName()) : List.of(type.getName());
            List<String> namespace = path.subList(0, path.size() - 1);
            types.set(id, new TypeEntry(id, namespace, path.get(path.size() - 1), describe(type)));
            return id;
        }

        /**
         * Whether a type becomes a named item in generated code (struct, union,
         * enum or typedef), so that a namespace path in its name is meaningful.
         * Pointers, arrays and built-ins are named after what they point to or hold.
         */
        private static boolean isNamedItem(DataType type) {
            return type instanceof Structure || type instanceof Union || type instanceof Enum
                || type instanceof TypeDef;
        }

        /** The id of a synthesised type, adding it on first use. */
        private int synthetic(String key, String name, TypeBody body) {
            Integer existing = typeIds.get(key);
            if (existing != null) {
                return existing;
            }
            int id = reserve(key);
            types.set(id, new TypeEntry(id, List.of(), name, body));
            return id;
        }

        /** Reserves an id before describing a type, so self-references terminate. */
        private int reserve(String key) {
            int id = types.size();
            typeIds.put(key, id);
            types.add(null);
            return id;
        }

        /** The id of an IR primitive. */
        private int primitive(String primitive) {
            return synthetic("imping:primitive:" + primitive, primitive, json -> {
                json.name("kind").value("primitive");
                json.name("primitive").value(primitive);
            });
        }

        private TypeBody primitiveBody(String primitive) {
            return json -> {
                json.name("kind").value("primitive");
                json.name("primitive").value(primitive);
            };
        }

        private TypeBody opaqueBody(int size) {
            return json -> {
                json.name("kind").value("opaque");
                if (size > 0) {
                    json.name("size").value(size);
                }
            };
        }

        /** The IR integer primitive of a size and signedness, if there is one. */
        private String integer(int size, boolean signed) {
            switch (size) {
                case 1:
                    return signed ? "i8" : "u8";
                case 2:
                    return signed ? "i16" : "u16";
                case 4:
                    return signed ? "i32" : "u32";
                case 8:
                    return signed ? "i64" : "u64";
                default:
                    return null;
            }
        }

        private TypeBody describe(DataType type) {
            if (type instanceof TypeDef typedef) {
                int target = typeId(typedef.getDataType());
                return json -> {
                    json.name("kind").value("typedef");
                    json.name("target").value(target);
                };
            }
            if (type instanceof Pointer pointer) {
                int size = pointer.getLength();
                if (size > 0 && size != program.getDefaultPointerSize()) {
                    // A pointer of another width (e.g. pointer32 in x64) is just an integer here.
                    String primitive = integer(size, false);
                    return primitive != null ? primitiveBody(primitive) : opaqueBody(size);
                }
                int pointee = typeId(pointer.getDataType());
                return json -> {
                    json.name("kind").value("pointer");
                    json.name("pointee").value(pointee);
                };
            }
            if (type instanceof Array array) {
                int element = typeId(array.getDataType());
                int count = array.getNumElements();
                return json -> {
                    json.name("kind").value("array");
                    json.name("element").value(element);
                    json.name("count").value(count);
                };
            }
            if (type instanceof Structure structure) {
                if (structure.isNotYetDefined()) {
                    return opaqueBody(0);
                }
                return composite("struct", structure.getLength(), structure.getAlignment(),
                    fields(structure.getDefinedComponents(), baseComponent(structure)));
            }
            if (type instanceof Union union) {
                if (union.isNotYetDefined()) {
                    return opaqueBody(0);
                }
                return composite("union", union.getLength(), union.getAlignment(),
                    fields(union.getDefinedComponents(), null));
            }
            if (type instanceof Enum enumeration) {
                String primitive = integer(enumeration.getLength(), enumeration.isSigned());
                if (primitive == null) {
                    return opaqueBody(enumeration.getLength());
                }
                int underlying = primitive(primitive);
                // Sorted by value, then name, for a stable order.
                TreeSet<String> names = new TreeSet<>((a, b) -> {
                    int byValue = Long.compare(enumeration.getValue(a), enumeration.getValue(b));
                    return byValue != 0 ? byValue : a.compareTo(b);
                });
                Collections.addAll(names, enumeration.getNames());
                return json -> {
                    json.name("kind").value("enum");
                    json.name("underlying").value(underlying);
                    json.name("variants").beginArray();
                    for (String name : names) {
                        json.beginObject();
                        json.name("name").value(name);
                        json.name("value").value(enumeration.getValue(name));
                        json.endObject();
                    }
                    json.endArray();
                };
            }
            if (type instanceof FunctionDefinition function) {
                String convention = convention(function.getCallingConventionName());
                List<Integer> parameters = new ArrayList<>();
                for (ParameterDefinition parameter : function.getArguments()) {
                    parameters.add(typeId(parameter.getDataType()));
                }
                int returnType = typeId(function.getReturnType());
                boolean variadic = function.hasVarArgs();
                return json -> {
                    json.name("kind").value("function");
                    json.name("calling_convention").value(convention);
                    json.name("parameters").beginArray();
                    for (int parameter : parameters) {
                        json.value(parameter);
                    }
                    json.endArray();
                    json.name("return_type").value(returnType);
                    json.name("variadic").value(variadic);
                };
            }
            if (type instanceof VoidDataType) {
                return primitiveBody("void");
            }
            if (type instanceof BooleanDataType) {
                return primitiveBody("bool");
            }
            if (type instanceof AbstractFloatDataType) {
                int size = type.getLength();
                return size == 4 ? primitiveBody("f32") : size == 8 ? primitiveBody("f64") : opaqueBody(size);
            }
            if (type instanceof CharDataType && type.getLength() == 1) {
                return primitiveBody("i8");
            }
            if (type instanceof WideCharDataType || type instanceof WideChar16DataType) {
                return primitiveBody("u16");
            }
            if (type instanceof WideChar32DataType) {
                return primitiveBody("u32");
            }
            if (type instanceof AbstractIntegerDataType integer) {
                String primitive = integer(integer.getLength(), integer.isSigned());
                return primitive != null ? primitiveBody(primitive) : opaqueBody(integer.getLength());
            }
            if (type instanceof Undefined || type instanceof DefaultDataType) {
                String primitive = integer(Math.max(type.getLength(), 1), false);
                return primitive != null ? primitiveBody(primitive) : opaqueBody(type.getLength());
            }
            return opaqueBody(type.getLength());
        }

        private TypeBody composite(String kind, int size, int align, List<FieldEntry> fields) {
            return json -> {
                json.name("kind").value(kind);
                json.name("size").value(size);
                json.name("align").value(Math.max(align, 1));
                json.name("fields").beginArray();
                for (FieldEntry field : fields) {
                    json.beginObject();
                    json.name("name").value(field.name());
                    json.name("type").value(field.type());
                    json.name("offset").value(field.offset());
                    if (field.base()) {
                        json.name("base").value(true);
                    }
                    if (field.isBitField()) {
                        json.name("bits").beginObject();
                        json.name("bit_offset").value(field.bitOffset());
                        json.name("bit_width").value(field.bitWidth());
                        json.endObject();
                    }
                    json.endObject();
                }
                json.endArray();
            };
        }

        /**
         * A composite's fields. Ghidra places a bitfield at the bytes it spans;
         * the IR places it in a storage unit of its declared type, aligned to
         * that type's size, so the bitfields sharing a unit share an offset.
         */
        private List<FieldEntry> fields(DataTypeComponent[] components, DataTypeComponent baseField) {
            List<FieldEntry> fields = new ArrayList<>();
            for (DataTypeComponent component : components) {
                String name = component.getFieldName();
                if (name == null || name.isEmpty()) {
                    name = component.getDefaultFieldName();
                }
                if (component.isBitFieldComponent()) {
                    BitFieldDataType bits = (BitFieldDataType) component.getDataType();
                    if (bits.getBitSize() == 0) {
                        continue;
                    }
                    DataType base = bits.getBaseDataType();
                    int unitSize = Math.max(base.getLength(), 1);
                    long position = component.getOffset() * 8L + bits.getBitOffset();
                    long unit = position / (unitSize * 8L) * unitSize;
                    long bitOffset = position - unit * 8;
                    if (bitOffset + bits.getBitSize() > unitSize * 8L) {
                        // Doesn't fit an aligned unit (packed layouts): keep Ghidra's placement.
                        unit = component.getOffset();
                        bitOffset = bits.getBitOffset();
                    }
                    fields.add(new FieldEntry(name, typeId(base), unit, (int) bitOffset, bits.getBitSize(),
                        false));
                } else {
                    fields.add(new FieldEntry(name, typeId(component.getDataType()),
                        component.getOffset(), 0, 0, component == baseField));
                }
            }
            return fields;
        }

        // --------------------------------------------------------- base classes

        /**
         * The field to mark as a struct's base class, or null. Where RTTI
         * describes a class of exactly the struct's name, the struct field at
         * offset 0 is the base when its type is a base RTTI places at offset 0
         * (template names compare without their arguments), whatever the field
         * is called; a field named {@code base} that RTTI contradicts is not
         * marked, and a warning says why. Otherwise a struct field at offset 0
         * named {@code base} is the base.
         */
        private DataTypeComponent baseComponent(Structure structure) {
            DataTypeComponent first = null;
            for (DataTypeComponent component : structure.getDefinedComponents()) {
                if (component.getOffset() == 0 && !component.isBitFieldComponent()) {
                    first = component;
                    break;
                }
            }
            Structure fieldType = first == null ? null : asStructure(first.getDataType());
            if (fieldType == null) {
                return null;
            }
            boolean namedBase = "base".equals(first.getFieldName());
            List<RttiBase> bases = rtti().get(normalize(structure.getName()));
            if (bases == null) {
                return namedBase ? first : null;
            }
            List<RttiBase> atZero = new ArrayList<>();
            for (RttiBase base : bases) {
                if (base.offset() == 0 && !base.isVirtual()) {
                    atZero.add(base);
                }
            }
            String field = normalize(fieldType.getName());
            for (RttiBase base : atZero) {
                String name = normalize(base.name());
                if (name.equals(field) || sameTemplate(name, field)) {
                    return first;
                }
            }
            if (namedBase && atZero.isEmpty()) {
                warnings.add(String.format(
                    "RTTI lists no base at offset 0 for %s, but its field `%s` there is named like a"
                        + " base; not marked as a base.",
                    structure.getName(), first.getFieldName()));
            } else if (namedBase) {
                warnings.add(String.format(
                    "RTTI lists %s's base at offset 0 as %s, but its field `%s` there is a %s; not"
                        + " marked as a base.",
                    structure.getName(), atZero.get(0).name(), first.getFieldName(), fieldType.getName()));
            }
            return null;
        }

        /** The structure a type is, through typedefs, or null. */
        private static Structure asStructure(DataType type) {
            DataType resolved = type instanceof TypeDef typedef ? typedef.getBaseDataType() : type;
            return resolved instanceof Structure structure ? structure : null;
        }

        /**
         * A C++ type name in one spelling: without `class`, `struct`, `union` or
         * `enum` keywords, `__ptr64` or whitespace.
         */
        private static String normalize(String name) {
            return name.replaceAll("\\b(class|struct|union|enum)\\s+", "")
                .replace("__ptr64", "")
                .replaceAll("\\s+", "");
        }

        /**
         * Whether two normalized names are the same template with other arguments,
         * such as `lib::Array<T>` and `lib::Array<cObj*>`. When one template name
         * has no namespace (`Array<T>`), only the last segments are compared.
         */
        private static boolean sameTemplate(String a, String b) {
            int left = a.indexOf('<');
            int right = b.indexOf('<');
            if (left <= 0 || right <= 0) {
                return false;
            }
            String first = a.substring(0, left);
            String second = b.substring(0, right);
            if (!first.contains("::") || !second.contains("::")) {
                first = first.substring(first.lastIndexOf(':') + 1);
                second = second.substring(second.lastIndexOf(':') + 1);
            }
            return first.equals(second);
        }

        /**
         * The base classes MSVC RTTI lists for each class, by normalized class
         * name: the classes of the class's base class array after the class
         * itself, with their offsets. Complete object locators are found in the
         * program's loaded, non-executable memory by their signature and the
         * reference to themselves that x64 RTTI carries. x86 RTTI carries none,
         * so x86 programs have no RTTI here and use the name fallback.
         */
        private Map<String, List<RttiBase>> rtti() {
            if (rttiClasses != null) {
                return rttiClasses;
            }
            rttiClasses = new HashMap<>();
            if (!x64) {
                return rttiClasses;
            }
            DataValidationOptions options = new DataValidationOptions();
            Map<Long, String> names = new HashMap<>();
            for (MemoryBlock block : memory.getBlocks()) {
                long start = rva(block.getStart());
                if (!block.isInitialized() || !block.isLoaded() || block.isExecute() || start < 0
                        || block.getSize() > Integer.MAX_VALUE) {
                    continue;
                }
                byte[] bytes = new byte[(int) block.getSize()];
                try {
                    block.getBytes(block.getStart(), bytes);
                } catch (MemoryAccessException e) {
                    continue;
                }
                ByteBuffer data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                for (int offset = 0; offset + 24 <= bytes.length; offset += 4) {
                    // Signature 1 (x64), and pSelf at +20 holds the locator's own RVA.
                    if (data.getInt(offset) != 1
                            || Integer.toUnsignedLong(data.getInt(offset + 20)) != start + offset) {
                        continue;
                    }
                    List<RttiBase> hierarchy =
                        hierarchy(Integer.toUnsignedLong(data.getInt(offset + 16)), names, options);
                    if (hierarchy != null && !hierarchy.isEmpty()) {
                        rttiClasses.putIfAbsent(normalize(hierarchy.get(0).name()),
                            hierarchy.subList(1, hierarchy.size()));
                    }
                }
            }
            return rttiClasses;
        }

        /**
         * The classes of a class hierarchy descriptor's base class array, the
         * class itself first, or null if it can't be read.
         */
        private List<RttiBase> hierarchy(long descriptor, Map<Long, String> names,
                DataValidationOptions options) {
            try {
                Address hierarchy = imageBase.add(descriptor);
                int count = memory.getInt(hierarchy.add(8));
                if (count <= 0 || count > 4096) {
                    return null;
                }
                Address array = imageBase.add(Integer.toUnsignedLong(memory.getInt(hierarchy.add(12))));
                List<RttiBase> classes = new ArrayList<>();
                for (int i = 0; i < count; i++) {
                    Address base =
                        imageBase.add(Integer.toUnsignedLong(memory.getInt(array.add(4L * i))));
                    long typeDescriptor = Integer.toUnsignedLong(memory.getInt(base));
                    String name = names.get(typeDescriptor);
                    if (name == null) {
                        name = className(typeDescriptor, options);
                        if (name == null) {
                            return null;
                        }
                        names.put(typeDescriptor, name);
                    }
                    // mdisp at +8; pdisp at +12 is -1 unless the base is virtual.
                    classes.add(new RttiBase(name, memory.getInt(base.add(8)),
                        memory.getInt(base.add(12)) >= 0));
                }
                return classes;
            } catch (MemoryAccessException | AddressOutOfBoundsException e) {
                return null;
            }
        }

        /** A type descriptor's class name with its namespace path, demangled by Ghidra, or null. */
        private String className(long typeDescriptor, DataValidationOptions options) {
            try {
                TypeDescriptorModel model =
                    new TypeDescriptorModel(program, imageBase.add(typeDescriptor), options);
                // The descriptor's "namespace" is the class's full path, the class included.
                String path = model.getDescriptorTypeNamespace();
                return path == null || path.isEmpty() ? model.getDescriptorName() : path;
            } catch (Exception e) {
                return null;
            }
        }

        // -------------------------------------------------------------- helpers

        private boolean isLoaded(Address address) {
            MemoryBlock block = memory.getBlock(address);
            return block != null && block.isLoaded();
        }

        /** The address relative to the image base, or -1 if it isn't a 32-bit RVA. */
        private long rva(Address address) {
            long rva = address.getOffset() - imageBase.getOffset();
            return rva >= 0 && rva <= 0xffff_ffffL ? rva : -1;
        }

        private String hex(long value) {
            return "0x" + Long.toHexString(value);
        }
    }
}
