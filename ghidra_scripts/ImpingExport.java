// Exports the current program as an imping IR file (JSON): its build identity,
// every function and global with a non-default name, and the types they use.
//
// Exported functions are the non-external functions whose names are not Ghidra
// defaults (not FUN_...), except the exception-handling funclets Ghidra's
// analysis names (Unwind@..., Catch@...). Exported globals are the data
// labels that are not defaults (not DAT_..., PTR_..., s_...). Types are
// exported only when an exported function or global uses them, directly or
// through other types.
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
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
    private static final int FORMAT_MINOR = 0;

    /** The most bytes recorded to verify a function's start before hooking it. */
    private static final int VERIFICATION_BYTES = 16;

    /** Names Ghidra's analysis gives exception-handling funclets. */
    private static final Pattern EXCEPTION_FUNCLET =
        Pattern.compile("(Unwind|Catch|Catch_All)@[0-9a-fA-F]+");

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

    /** A type in the IR's type table. */
    private record TypeEntry(int id, String name, TypeBody body) {}

    /** Writes the kind-specific part of a type entry. */
    @FunctionalInterface
    private interface TypeBody {
        void write(JsonWriter json) throws IOException;
    }

    /** One field of a struct or union, resolved to type ids. */
    private record FieldEntry(String name, int type, long offset, int bitOffset, int bitWidth) {
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
        private final Map<String, Integer> typeIds = new HashMap<>();

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
            types.set(id, new TypeEntry(id, type.getName(), describe(type)));
            return id;
        }

        /** The id of a synthesised type, adding it on first use. */
        private int synthetic(String key, String name, TypeBody body) {
            Integer existing = typeIds.get(key);
            if (existing != null) {
                return existing;
            }
            int id = reserve(key);
            types.set(id, new TypeEntry(id, name, body));
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
                    fields(structure.getDefinedComponents()));
            }
            if (type instanceof Union union) {
                if (union.isNotYetDefined()) {
                    return opaqueBody(0);
                }
                return composite("union", union.getLength(), union.getAlignment(),
                    fields(union.getDefinedComponents()));
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
        private List<FieldEntry> fields(DataTypeComponent[] components) {
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
                    fields.add(new FieldEntry(name, typeId(base), unit, (int) bitOffset, bits.getBitSize()));
                } else {
                    fields.add(new FieldEntry(name, typeId(component.getDataType()),
                        component.getOffset(), 0, 0));
                }
            }
            return fields;
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
