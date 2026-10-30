// Exports the current program as an imping IR file (JSON): its build identity,
// the functions and globals with non-default names, and the types they use.
//
// Names Ghidra generated (FUN_..., DAT_..., Unwind@..., switchdataD_..., RTTI
// labels) are skipped. A struct's field at offset 0 is marked as its base class
// when x64 RTTI says so, or else when the field is named `base`. Each function
// also gets a byte pattern that finds it if a later build moves it.
//
// In the GUI the script asks where to save the file. Headless, pass the output
// path as the script's argument:
//
//   analyzeHeadless <project dir> <project> -process <program> -noanalysis
//       -scriptPath <imping-ghidra>/ghidra_scripts
//       -postScript ImpingExport.java <output.ir.json>
//
// Supports x86 and x64 PE programs only.
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
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Instruction;
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
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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
import java.util.Arrays;
import java.util.Collection;
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
    private static final int FORMAT_MINOR = 2;

    /** The most bytes recorded to verify a function's start before hooking it. */
    private static final int VERIFICATION_BYTES = 16;

    /** The longest byte pattern, in bytes. */
    private static final int PATTERN_BYTES = 64;

    /** The most calls tried for a function whose own bytes aren't unique. */
    private static final int PATTERN_CALL_SITES = 10;

    /** The most instructions before a call that a pattern may start at. */
    private static final int PATTERN_LEAD = 3;

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
        println(String.format(
            "imping: exported %d functions (%d with byte patterns), %d globals and %d types to %s",
            exporter.functions.size(), exporter.patterns.size(), exporter.globals.size(),
            exporter.types.size(), output));
    }

    /** Returns the output file: the script's argument, or else one the user picks. */
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

    /** One base class RTTI lists for a class: its name, offset and whether it's virtual. */
    private record RttiBase(String name, int offset, boolean isVirtual) {}

    /** One field of a struct or union, resolved to type ids. */
    private record FieldEntry(String name, int type, long offset, int bitOffset, int bitWidth,
            boolean base) {
        boolean isBitField() {
            return bitWidth > 0;
        }
    }

    /**
     * A byte pattern that matches one function alone: its bytes, which of them are fixed, and
     * whether it matches a call to the function, `offset` bytes in, rather than the function
     * itself.
     */
    private record BytePattern(byte[] bytes, boolean[] fixed, int length, int offset,
            boolean followCall) {
        /** Returns the pattern as imping reads it, e.g. `48 8b ?? 57`, minus trailing wildcards. */
        String text() {
            int end = length;
            while (end > 0 && !fixed[end - 1]) {
                end--;
            }
            StringBuilder text = new StringBuilder(end * 3);
            for (int i = 0; i < end; i++) {
                if (i > 0) {
                    text.append(' ');
                }
                text.append(fixed[i] ? String.format("%02x", bytes[i] & 0xff) : "??");
            }
            return text.toString();
        }
    }

    /**
     * Instructions read for a pattern: their bytes, which of them are fixed, where each
     * instruction ends, and where the call is if it's read for a call to the function.
     */
    private record Sequence(Address start, byte[] bytes, boolean[] fixed, int[] ends,
            boolean followCall, int callAt) {
        /** Returns how far a pattern must reach: past the call's displacement, if there's one. */
        int minimum() {
            return followCall ? callAt + 5 : 0;
        }

        /** Returns where the first three fixed bytes in a row start, or -1. */
        int anchor() {
            int length = ends[ends.length - 1];
            for (int i = 0; i + 3 <= length; i++) {
                if (fixed[i] && fixed[i + 1] && fixed[i + 2]) {
                    return i;
                }
            }
            return -1;
        }
    }

    /** A growable list of longs. */
    private static final class LongList {
        long[] items = new long[16];
        int size;

        void add(long item) {
            if (size == items.length) {
                items = Arrays.copyOf(items, size * 2);
            }
            items[size++] = item;
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
        final Map<Function, BytePattern> patterns = new HashMap<>();
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
            // Functions first, then globals, so type ids come out the same every run.
            for (Function function : functions) {
                typeId(function.getReturnType());
                for (Parameter parameter : parameters(function)) {
                    typeId(parameter.getDataType());
                }
            }
            for (GlobalItem global : globals) {
                globalType(global.data());
            }
            patterns.putAll(new PatternMaker(program).find(functions));
            List<String> unmatched = new ArrayList<>();
            for (Function function : functions) {
                if (!patterns.containsKey(function)) {
                    unmatched.add(function.getName(true));
                }
            }
            if (!unmatched.isEmpty()) {
                // Often thousands, mostly tiny or identical functions, so only a few are named.
                int named = Math.min(unmatched.size(), 10);
                String rest = unmatched.size() > named
                    ? " and " + (unmatched.size() - named) + " more" : "";
                warnings.add("no unique byte pattern for " + unmatched.size()
                    + " functions, so they can't be found if they move (mostly tiny or identical"
                    + " ones): " + String.join(", ", unmatched.subList(0, named)) + rest);
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
            BytePattern pattern = patterns.get(function);
            if (pattern != null) {
                json.name("pattern").beginObject();
                json.name("bytes").value(pattern.text());
                if (pattern.offset() != 0) {
                    json.name("offset").value(pattern.offset());
                }
                if (pattern.followCall()) {
                    json.name("follow_call").value(true);
                }
                json.endObject();
            }
            json.endObject();
        }

        /**
         * Writes a parameter's storage, returning false if it isn't a single register or
         * stack slot (the function then needs custom storage).
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
         * Splits a C++ name at its top-level {@code ::} into namespace segments and the name.
         *
         * <p>Template arguments and parenthesised lists stay whole, so
         * {@code lib::Array<hap::Token>} splits into {@code [lib, Array<hap::Token>]}.
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

        /** Returns the module's file name, as the process loads it. */
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

        /** Returns the PE NT headers' address, via the headers Ghidra maps at the image base. */
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
         * Returns whether a function is an exception-handling funclet named by Ghidra's analysis.
         *
         * <p>Funclets (Unwind@..., Catch@..., Catch_All@...) are compiler-generated pieces of
         * other functions, not something to call or hook. A name a user chose is still exported.
         */
        private boolean isExceptionFunclet(Function function) {
            return function.getSymbol().getSource() == SourceType.ANALYSIS
                && EXCEPTION_FUNCLET.matcher(function.getName()).matches();
        }

        /**
         * Returns whether a data label was generated rather than chosen.
         *
         * <p>That's any label from Ghidra's analysis (switchdataD_..., thread-block fields)
         * and the RTTI metadata labels from class recovery (RTTI_..., vftable_meta_ptr).
         * vftable labels are kept.
         */
        private boolean isGeneratedDataLabel(Symbol symbol) {
            return symbol.getSource() == SourceType.ANALYSIS
                || RTTI_METADATA.matcher(symbol.getName()).matches();
        }

        /** Returns a function's parameters, without a hidden return-storage pointer. */
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

        /** Lowercases a register name and drops Ghidra's sub-register suffix (XMM1_Qa). */
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
         * Returns a function's first bytes as hex, stopping at the end of its first address
         * range or at the first byte the loader relocates.
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

        /** Returns the type id of a global's data, sizing variable-length data such as strings. */
        private int globalType(Data data) {
            DataType type = data.getDataType();
            if (type.getLength() > 0 || data.getLength() <= 0) {
                return typeId(type);
            }
            // Variable length, like a string: an array of Ghidra's character types,
            // so it's still recognised as text.
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

        /** Returns the id of a Ghidra data type, adding it and the types it uses on first use. */
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
         * Returns whether a type is a struct, union, enum or typedef, whose name can hold a
         * namespace path.
         *
         * <p>Pointers, arrays and built-ins are named after what they point to or hold, so
         * their names aren't split.
         */
        private static boolean isNamedItem(DataType type) {
            return type instanceof Structure || type instanceof Union || type instanceof Enum
                || type instanceof TypeDef;
        }

        /** Returns the id of a synthesised type, adding it on first use. */
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

        /** Returns the id of an IR primitive, adding it on first use. */
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

        /** Returns the IR integer primitive of a size and signedness, or null if there's none. */
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
            // uchar and schar are CharDataTypes too; plain char is signed in MSVC's data layout.
            if (type instanceof CharDataType character && type.getLength() == 1) {
                return primitiveBody(character.isSigned() ? "i8" : "u8");
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
         * Converts a composite's components to IR fields.
         *
         * <p>Ghidra places a bitfield at the bytes it spans; the IR places it in a storage
         * unit of its declared type, aligned to that type's size, so bitfields sharing a
         * unit share an offset.
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
         * Returns the field to mark as a struct's base class, or null.
         *
         * <p>If RTTI describes a class of the struct's exact name, the struct field at offset 0,
         * whatever its name, is the base when RTTI puts its type at offset 0 as a non-virtual
         * base (templates compare without arguments); a {@code base} field RTTI contradicts
         * gets a warning instead. Without such RTTI, a struct field at offset 0 named
         * {@code base} is the base.
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

        /** Returns the structure a type is, looking through typedefs, or null. */
        private static Structure asStructure(DataType type) {
            DataType resolved = type instanceof TypeDef typedef ? typedef.getBaseDataType() : type;
            return resolved instanceof Structure structure ? structure : null;
        }

        /**
         * Normalizes a C++ type name by dropping class, struct, union and enum keywords,
         * {@code __ptr64} and whitespace.
         */
        private static String normalize(String name) {
            return name.replaceAll("\\b(class|struct|union|enum)\\s+", "")
                .replace("__ptr64", "")
                .replaceAll("\\s+", "");
        }

        /**
         * Returns whether two normalized names are the same template, such as
         * {@code lib::Array<T>} and {@code lib::Array<cObj*>}.
         *
         * <p>If either has no namespace ({@code Array<T>}), only the last segments are compared.
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
         * Returns the base classes MSVC RTTI lists for each class, by normalized class name.
         *
         * <p>Finds complete object locators in loaded, non-executable memory by their signature
         * and the self-reference x64 RTTI carries. x86 locators have none, so x86 programs get
         * an empty map and fall back to field names.
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
         * Returns the classes in a class hierarchy descriptor's base class array, the class
         * itself first, or null if it can't be read.
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

        /** Returns a type descriptor's demangled class name with its namespace path, or null. */
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

        /** Returns an address relative to the image base, or -1 if that isn't a 32-bit RVA. */
        private long rva(Address address) {
            long rva = address.getOffset() - imageBase.getOffset();
            return rva >= 0 && rva <= 0xffff_ffffL ? rva : -1;
        }

        private String hex(long value) {
            return "0x" + Long.toHexString(value);
        }
    }

    /**
     * Finds a byte pattern for each function that matches it once among the program's executable
     * bytes, as imping's runtime searches them. A pattern grows an instruction at a time from the
     * entry, within the function; if the function ends first, it grows from a call to the function
     * instead. Bytes that hold addresses are wildcards, so code that moved still matches.
     */
    private final class PatternMaker {
        private final Program program;
        private final Listing listing;
        private final List<MemoryBlock> blocks = new ArrayList<>();
        private final List<byte[]> contents = new ArrayList<>();
        /** Where each wanted 3-byte anchor occurs, as {@link #pack}ed positions. */
        private final Map<Integer, LongList> anchors = new HashMap<>();
        private long[] candidates = new long[1024];

        PatternMaker(Program program) throws MemoryAccessException {
            this.program = program;
            this.listing = program.getListing();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isExecute() && block.isInitialized() && block.isLoaded()) {
                    byte[] bytes = new byte[(int) block.getSize()];
                    block.getBytes(block.getStart(), bytes);
                    blocks.add(block);
                    contents.add(bytes);
                }
            }
        }

        Map<Function, BytePattern> find(List<Function> functions) throws Exception {
            monitor.setMessage("imping: finding byte patterns");
            Map<Function, BytePattern> found = new HashMap<>();
            Map<Function, Sequence> entries = new HashMap<>();
            for (Function function : functions) {
                monitor.checkCancelled();
                Address entry = function.getEntryPoint();
                AddressRange range = function.getBody().getRangeContaining(entry);
                Instruction first = listing.getInstructionAt(entry);
                Sequence sequence =
                    range == null || first == null ? null : sequence(first, range, false, 0);
                if (sequence != null) {
                    entries.put(function, sequence);
                }
            }
            index(entries.values());
            List<Function> pending = new ArrayList<>();
            for (Function function : functions) {
                monitor.checkCancelled();
                Sequence sequence = entries.get(function);
                BytePattern pattern = sequence == null ? null : unique(sequence);
                if (pattern != null) {
                    found.put(function, pattern);
                } else {
                    pending.add(function);
                }
            }

            Map<Function, List<Sequence>> calls = new HashMap<>();
            List<Sequence> all = new ArrayList<>();
            for (Function function : pending) {
                monitor.checkCancelled();
                List<Sequence> sequences = callSequences(function);
                calls.put(function, sequences);
                all.addAll(sequences);
            }
            index(all);
            for (Function function : pending) {
                monitor.checkCancelled();
                BytePattern best = null;
                for (Sequence sequence : calls.get(function)) {
                    BytePattern pattern = unique(sequence);
                    if (pattern != null && (best == null || pattern.length() < best.length())) {
                        best = pattern;
                    }
                }
                if (best != null) {
                    found.put(function, best);
                }
            }
            return found;
        }

        /**
         * Returns sequences around direct calls or jumps to a function from inside others: from
         * the call, and from each of the few instructions before it.
         */
        private List<Sequence> callSequences(Function function) {
            List<Sequence> sequences = new ArrayList<>();
            ReferenceIterator references =
                program.getReferenceManager().getReferencesTo(function.getEntryPoint());
            int calls = 0;
            while (references.hasNext() && calls < PATTERN_CALL_SITES) {
                Address from = references.next().getFromAddress();
                Instruction call = listing.getInstructionAt(from);
                Function caller = listing.getFunctionContaining(from);
                AddressRange range = caller == null ? null : caller.getBody().getRangeContaining(from);
                if (call == null || range == null || !isDirectCall(call)) {
                    continue;
                }
                calls++;
                Instruction start = call;
                for (int lead = 0; lead <= PATTERN_LEAD && start != null; lead++) {
                    int callAt = (int) from.subtract(start.getMinAddress());
                    Sequence sequence = sequence(start, range, true, callAt);
                    if (sequence != null) {
                        sequences.add(sequence);
                    }
                    Instruction previous = listing.getInstructionBefore(start.getMinAddress());
                    boolean adjacent = previous != null && range.contains(previous.getMinAddress())
                        && previous.getMaxAddress().next().equals(start.getMinAddress());
                    start = adjacent ? previous : null;
                }
            }
            return sequences;
        }

        /** Whether an instruction is a `call` or `jmp` with a 32-bit displacement, E8 or E9. */
        private boolean isDirectCall(Instruction instruction) {
            try {
                byte opcode = instruction.getByte(0);
                return instruction.getLength() == 5 && (opcode == (byte) 0xe8 || opcode == (byte) 0xe9);
            } catch (MemoryAccessException e) {
                return false;
            }
        }

        /**
         * Reads instructions from `first` while they follow on from each other inside `range`, up
         * to the longest pattern.
         */
        private Sequence sequence(Instruction first, AddressRange range, boolean followCall,
                int callAt) {
            byte[] bytes = new byte[PATTERN_BYTES];
            boolean[] fixed = new boolean[PATTERN_BYTES];
            int[] ends = new int[PATTERN_BYTES];
            int length = 0;
            int count = 0;
            Instruction instruction = first;
            while (instruction != null && range.contains(instruction.getMaxAddress())) {
                byte[] own;
                try {
                    own = instruction.getBytes();
                } catch (MemoryAccessException e) {
                    break;
                }
                if (length + own.length > PATTERN_BYTES) {
                    break;
                }
                boolean[] wild = wildcards(instruction, own.length);
                for (int i = 0; i < own.length; i++) {
                    bytes[length + i] = own[i];
                    fixed[length + i] = !wild[i];
                }
                length += own.length;
                ends[count++] = length;
                Instruction next = instruction.getNext();
                Address after = instruction.getMaxAddress().next();
                instruction = next != null && next.getMinAddress().equals(after) ? next : null;
            }
            return count == 0 || followCall && length < callAt + 5 ? null
                : new Sequence(first.getMinAddress(), bytes, fixed, Arrays.copyOf(ends, count),
                    followCall, callAt);
        }

        /**
         * Returns which of an instruction's bytes hold an address: a branch target, a
         * RIP-relative displacement, or anything the loader relocates.
         */
        private boolean[] wildcards(Instruction instruction, int length) {
            boolean[] wild = new boolean[length];
            InstructionPrototype prototype = instruction.getPrototype();
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                Mask mask = holdsAddress(instruction, operand)
                    ? prototype.getOperandValueMask(operand) : null;
                if (mask == null) {
                    continue;
                }
                byte[] bits = mask.getBytes();
                for (int i = 0; i < Math.min(length, bits.length); i++) {
                    // Whole bytes only: a ModR/M byte also holds the opcode's and registers' bits.
                    if (bits[i] == (byte) 0xff) {
                        wild[i] = true;
                    }
                }
            }
            Address start = instruction.getMinAddress();
            Iterator<Relocation> relocations = program.getRelocationTable()
                .getRelocations(new AddressSet(start, instruction.getMaxAddress()));
            while (relocations.hasNext()) {
                Relocation relocation = relocations.next();
                long from = relocation.getAddress().subtract(start);
                long to = from + Math.max(relocation.getLength(), 1);
                for (long i = Math.max(from, 0); i < Math.min(to, length); i++) {
                    wild[(int) i] = true;
                }
            }
            return wild;
        }

        private boolean holdsAddress(Instruction instruction, int operand) {
            if (OperandType.isRelative(instruction.getOperandType(operand))) {
                return true;
            }
            for (Reference reference : instruction.getOperandReferences(operand)) {
                if (reference.getToAddress().isMemoryAddress() && !reference.isStackReference()) {
                    return true;
                }
            }
            for (Object object : instruction.getOpObjects(operand)) {
                if (object instanceof Register register && register.getName().equalsIgnoreCase("rip")) {
                    return true;
                }
            }
            return false;
        }

        /** Records where each sequence's anchor occurs, in one pass over the executable bytes. */
        private void index(Collection<Sequence> sequences) throws Exception {
            anchors.clear();
            boolean[] wanted = new boolean[1 << 24];
            for (Sequence sequence : sequences) {
                int anchor = sequence.anchor();
                if (anchor >= 0) {
                    int key = key(sequence.bytes(), anchor);
                    wanted[key] = true;
                    anchors.computeIfAbsent(key, k -> new LongList());
                }
            }
            for (int block = 0; block < contents.size(); block++) {
                monitor.checkCancelled();
                byte[] bytes = contents.get(block);
                for (int i = 0; i + 3 <= bytes.length; i++) {
                    int key = key(bytes, i);
                    if (wanted[key]) {
                        anchors.get(key).add(pack(block, i));
                    }
                }
            }
        }

        /**
         * Returns the shortest start of `sequence`, ending after an instruction, that matches
         * nowhere else, or null.
         */
        private BytePattern unique(Sequence sequence) {
            int anchor = sequence.anchor();
            long own = position(sequence.start());
            if (anchor < 0 || own < 0) {
                return null;
            }
            // Every place the anchor occurs, moved back to where the sequence would start.
            LongList positions = anchors.get(key(sequence.bytes(), anchor));
            if (candidates.length < positions.size) {
                candidates = new long[positions.size];
            }
            int count = 0;
            for (int i = 0; i < positions.size; i++) {
                long position = positions.items[i];
                int start = offset(position) - anchor;
                if (start >= 0) {
                    candidates[count++] = pack(block(position), start);
                }
            }
            int checked = 0;
            for (int end : sequence.ends()) {
                int kept = 0;
                for (int i = 0; i < count; i++) {
                    if (matches(sequence, candidates[i], checked, end)) {
                        candidates[kept++] = candidates[i];
                    }
                }
                count = kept;
                checked = end;
                if (end >= anchor + 3 && end >= sequence.minimum() && count <= 1) {
                    return count == 1 && candidates[0] == own
                        ? new BytePattern(sequence.bytes(), sequence.fixed(), end,
                            sequence.callAt(), sequence.followCall())
                        : null;
                }
            }
            return null;
        }

        /** Whether the fixed bytes `from` to `to` of a sequence match at a position. */
        private boolean matches(Sequence sequence, long position, int from, int to) {
            byte[] bytes = contents.get(block(position));
            int start = offset(position);
            if (start + to > bytes.length) {
                return false;
            }
            for (int i = from; i < to; i++) {
                if (sequence.fixed()[i] && bytes[start + i] != sequence.bytes()[i]) {
                    return false;
                }
            }
            return true;
        }

        /** Returns an address's packed position in the executable bytes, or -1. */
        private long position(Address address) {
            for (int block = 0; block < blocks.size(); block++) {
                if (blocks.get(block).contains(address)) {
                    return pack(block, (int) address.subtract(blocks.get(block).getStart()));
                }
            }
            return -1;
        }

        private static int key(byte[] bytes, int at) {
            return (bytes[at] & 0xff) << 16 | (bytes[at + 1] & 0xff) << 8 | bytes[at + 2] & 0xff;
        }

        private static long pack(int block, int offset) {
            return (long) block << 32 | offset & 0xffff_ffffL;
        }

        private static int block(long position) {
            return (int) (position >>> 32);
        }

        private static int offset(long position) {
            return (int) position;
        }
    }
}
