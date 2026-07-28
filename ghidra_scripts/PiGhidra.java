//@category Pi

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.CancelledException;

public class PiGhidra extends GhidraScript {
    private static final int MAX_LIMIT = 2000;
    private static final int MAX_MEMORY = 1024 * 1024;
    private static final long MAX_SEARCH = 64L * 1024 * 1024;
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private DecompInterface decompiler;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected request and response paths");
        Path requestPath = Path.of(args[0]);
        Path responsePath = Path.of(args[1]);
        JsonObject response = new JsonObject();
        try {
            JsonObject request = JsonParser.parseString(Files.readString(requestPath)).getAsJsonObject();
            response.addProperty("ok", true);
            response.add("result", execute(request));
            write(responsePath, response);
        } catch (Throwable error) {
            response = new JsonObject();
            response.addProperty("ok", false);
            response.addProperty("error", error.getClass().getSimpleName() + ": " + String.valueOf(error.getMessage()));
            write(responsePath, response);
            if (error instanceof Exception) throw (Exception) error;
            throw new RuntimeException(error);
        } finally {
            if (decompiler != null) decompiler.dispose();
        }
    }

    private void write(Path path, JsonObject value) throws IOException {
        Files.createDirectories(path.getParent());
        Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
        Files.writeString(temporary, gson.toJson(value), StandardCharsets.UTF_8);
        Files.move(temporary, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private JsonElement execute(JsonObject request) throws Exception {
        String action = string(request, "action", true);
        if ("batch".equals(action)) {
            JsonArray results = new JsonArray();
            JsonArray operations = request.getAsJsonArray("operations");
            if (operations == null || operations.size() == 0) throw new IllegalArgumentException("operations is required for batch");
            for (JsonElement element : operations) {
                monitor.checkCancelled();
                JsonObject operation = element.getAsJsonObject();
                JsonObject item = new JsonObject();
                item.addProperty("action", string(operation, "action", true));
                item.add("result", execute(operation));
                results.add(item);
            }
            return results;
        }
        if ("info".equals(action)) return info();
        if ("analyze".equals(action)) return continueAnalysis();
        if ("memory_blocks".equals(action)) return memoryBlocks();
        if ("entry_points".equals(action)) return entryPoints();
        if ("functions".equals(action)) return functions(request);
        if ("function".equals(action)) return functionJson(resolveFunction(request));
        if ("decompile".equals(action)) return decompile(request);
        if ("disassemble".equals(action)) return disassemble(request);
        if ("data".equals(action)) return data(request);
        if ("strings".equals(action)) return strings(request);
        if ("symbols".equals(action)) return symbols(request);
        if ("imports".equals(action)) return imports(request);
        if ("exports".equals(action)) return exports(request);
        if ("references".equals(action)) return references(request);
        if ("call_graph".equals(action)) return callGraph(request);
        if ("memory".equals(action)) return memory(request);
        if ("search_bytes".equals(action)) return searchBytes(request);
        if ("search_text".equals(action)) return searchText(request);
        if ("analysis_options".equals(action)) return analysisOptions();
        if ("set_analysis_options".equals(action)) return setAnalysisOptions(request);
        if ("reanalyze".equals(action)) return reanalyze();
        if ("rename".equals(action)) return rename(request);
        if ("comment".equals(action)) return comment(request);
        if ("patch".equals(action)) return patch(request);
        throw new IllegalArgumentException("Unknown action: " + action);
    }

    private JsonObject info() {
        JsonObject result = new JsonObject();
        result.addProperty("name", currentProgram.getName());
        result.addProperty("executablePath", currentProgram.getExecutablePath());
        result.addProperty("format", currentProgram.getExecutableFormat());
        result.addProperty("md5", currentProgram.getExecutableMD5());
        result.addProperty("sha256", currentProgram.getExecutableSHA256());
        result.addProperty("language", currentProgram.getLanguage().getLanguageID().toString());
        result.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("imageBase", address(currentProgram.getImageBase()));
        result.addProperty("minAddress", address(currentProgram.getMinAddress()));
        result.addProperty("maxAddress", address(currentProgram.getMaxAddress()));
        result.addProperty("pointerSize", currentProgram.getDefaultPointerSize());
        result.addProperty("functionCount", currentProgram.getFunctionManager().getFunctionCount());
        result.addProperty("symbolCount", currentProgram.getSymbolTable().getNumSymbols());
        return result;
    }

    private JsonArray memoryBlocks() {
        JsonArray result = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject item = new JsonObject();
            item.addProperty("name", block.getName());
            item.addProperty("start", address(block.getStart()));
            item.addProperty("end", address(block.getEnd()));
            item.addProperty("size", block.getSize());
            item.addProperty("initialized", block.isInitialized());
            item.addProperty("read", block.isRead());
            item.addProperty("write", block.isWrite());
            item.addProperty("execute", block.isExecute());
            item.addProperty("volatile", block.isVolatile());
            result.add(item);
        }
        return result;
    }

    private JsonArray entryPoints() {
        JsonArray result = new JsonArray();
        AddressIterator iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            Address entry = iterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("address", address(entry));
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(entry);
            if (symbol != null) item.addProperty("name", symbol.getName(true));
            result.add(item);
        }
        return result;
    }

    private JsonArray functions(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        String query = string(request, "query", false);
        query = query == null ? null : query.toLowerCase();
        JsonArray result = new JsonArray();
        int matched = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (query != null && !function.getName(true).toLowerCase().contains(query)) continue;
            if (matched++ < offset) continue;
            result.add(functionJson(function));
        }
        return result;
    }

    private JsonObject functionJson(Function function) {
        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName(true));
        result.addProperty("entry", address(function.getEntryPoint()));
        result.addProperty("signature", function.getPrototypeString(true, true));
        result.addProperty("callingConvention", function.getCallingConventionName());
        result.addProperty("returnType", function.getReturnType().getDisplayName());
        result.addProperty("external", function.isExternal());
        result.addProperty("thunk", function.isThunk());
        result.addProperty("noReturn", function.hasNoReturn());
        result.addProperty("varArgs", function.hasVarArgs());
        result.addProperty("bodySize", function.getBody().getNumAddresses());
        JsonArray parameters = new JsonArray();
        for (Parameter parameter : function.getParameters()) parameters.add(variableJson(parameter));
        result.add("parameters", parameters);
        JsonArray locals = new JsonArray();
        for (Variable local : function.getLocalVariables()) locals.add(variableJson(local));
        result.add("locals", locals);
        return result;
    }

    private JsonObject variableJson(Variable variable) {
        JsonObject result = new JsonObject();
        result.addProperty("name", variable.getName());
        result.addProperty("type", variable.getDataType().getDisplayName());
        result.addProperty("length", variable.getLength());
        result.addProperty("storage", variable.getVariableStorage().toString());
        return result;
    }

    private JsonObject decompile(JsonObject request) throws Exception {
        Function function = resolveFunction(request);
        if (decompiler == null) {
            decompiler = new DecompInterface();
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        }
        int timeout = integer(request, "timeoutSeconds", 60, 1, 600);
        DecompileResults output = decompiler.decompileFunction(function, timeout, monitor);
        if (!output.decompileCompleted()) throw new IllegalStateException(output.getErrorMessage());
        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName(true));
        result.addProperty("entry", address(function.getEntryPoint()));
        result.addProperty("signature", output.getDecompiledFunction().getSignature());
        result.addProperty("code", output.getDecompiledFunction().getC());
        return result;
    }

    private JsonArray disassemble(JsonObject request) throws Exception {
        Function function = has(request, "name") || has(request, "address") ? resolveFunction(request) : null;
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        InstructionIterator iterator = function == null
            ? currentProgram.getListing().getInstructions(true)
            : currentProgram.getListing().getInstructions(function.getBody(), true);
        JsonArray result = new JsonArray();
        int seen = 0;
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (seen++ < offset) continue;
            JsonObject item = new JsonObject();
            item.addProperty("address", address(instruction.getAddress()));
            item.addProperty("mnemonic", instruction.getMnemonicString());
            item.addProperty("text", instruction.toString());
            item.addProperty("bytes", hex(instruction.getBytes()));
            result.add(item);
        }
        return result;
    }

    private JsonArray data(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        JsonArray result = new JsonArray();
        int seen = 0;
        DataIterator iterator = currentProgram.getListing().getDefinedData(true);
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Data value = iterator.next();
            if (seen++ < offset) continue;
            JsonObject item = new JsonObject();
            item.addProperty("address", address(value.getAddress()));
            item.addProperty("type", value.getDataType().getDisplayName());
            item.addProperty("length", value.getLength());
            item.addProperty("value", value.getDefaultValueRepresentation());
            result.add(item);
        }
        return result;
    }

    private JsonArray strings(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        String query = string(request, "query", false);
        query = query == null ? null : query.toLowerCase();
        JsonArray result = new JsonArray();
        int matched = 0;
        for (Data data : DefinedDataIterator.byDataInstance(currentProgram, value -> StringDataInstance.getStringDataInstance(value) != null)) {
            monitor.checkCancelled();
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            String value = instance == null ? data.getDefaultValueRepresentation() : instance.getStringValue();
            if (value == null || (query != null && !value.toLowerCase().contains(query))) continue;
            if (matched++ < offset) continue;
            JsonObject item = new JsonObject();
            item.addProperty("address", address(data.getAddress()));
            item.addProperty("length", data.getLength());
            item.addProperty("value", value);
            result.add(item);
            if (result.size() >= limit) break;
        }
        return result;
    }

    private JsonArray symbols(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        String query = string(request, "query", false);
        query = query == null ? null : query.toLowerCase();
        JsonArray result = new JsonArray();
        int matched = 0;
        SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Symbol symbol = iterator.next();
            if (query != null && !symbol.getName(true).toLowerCase().contains(query)) continue;
            if (matched++ < offset) continue;
            result.add(symbolJson(symbol));
        }
        return result;
    }

    private JsonObject symbolJson(Symbol symbol) {
        JsonObject result = new JsonObject();
        result.addProperty("name", symbol.getName(true));
        result.addProperty("address", address(symbol.getAddress()));
        result.addProperty("type", symbol.getSymbolType().toString());
        result.addProperty("source", symbol.getSource().toString());
        result.addProperty("primary", symbol.isPrimary());
        result.addProperty("dynamic", symbol.isDynamic());
        return result;
    }

    private JsonArray imports(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        JsonArray result = new JsonArray();
        int seen = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getExternalFunctions();
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (seen++ < offset) continue;
            JsonObject item = functionJson(function);
            ExternalLocation location = function.getExternalLocation();
            if (location != null) {
                item.addProperty("library", location.getLibraryName());
                item.addProperty("label", location.getLabel());
            }
            result.add(item);
        }
        return result;
    }

    private JsonArray exports(JsonObject request) throws CancelledException {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        JsonArray result = new JsonArray();
        int seen = 0;
        AddressIterator iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext() && result.size() < limit) {
            monitor.checkCancelled();
            Address value = iterator.next();
            if (seen++ < offset) continue;
            JsonObject item = new JsonObject();
            item.addProperty("address", address(value));
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(value);
            if (symbol != null) item.addProperty("name", symbol.getName(true));
            result.add(item);
        }
        return result;
    }

    private JsonArray references(JsonObject request) throws Exception {
        Address target = resolveAddress(request);
        String direction = string(request, "direction", false);
        direction = direction == null ? "both" : direction;
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        JsonArray result = new JsonArray();
        if (!"from".equals(direction)) {
            ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(target);
            while (iterator.hasNext() && result.size() < limit) result.add(referenceJson(iterator.next(), "to"));
        }
        if (!"to".equals(direction)) {
            for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(target)) {
                if (result.size() >= limit) break;
                result.add(referenceJson(reference, "from"));
            }
        }
        return result;
    }

    private JsonObject referenceJson(Reference reference, String direction) {
        JsonObject result = new JsonObject();
        result.addProperty("direction", direction);
        result.addProperty("from", address(reference.getFromAddress()));
        result.addProperty("to", address(reference.getToAddress()));
        result.addProperty("type", reference.getReferenceType().getName());
        result.addProperty("operand", reference.getOperandIndex());
        result.addProperty("primary", reference.isPrimary());
        return result;
    }

    private JsonObject callGraph(JsonObject request) throws Exception {
        Function function = resolveFunction(request);
        int limit = integer(request, "limit", 200, 1, MAX_LIMIT);
        JsonObject result = new JsonObject();
        result.add("function", functionJson(function));
        result.add("callers", functionSet(function.getCallingFunctions(monitor), limit));
        result.add("callees", functionSet(function.getCalledFunctions(monitor), limit));
        return result;
    }

    private JsonArray functionSet(Set<Function> functions, int limit) {
        JsonArray result = new JsonArray();
        for (Function function : functions) {
            result.add(functionJson(function));
            if (result.size() >= limit) break;
        }
        return result;
    }

    private JsonObject memory(JsonObject request) throws Exception {
        Address start = resolveAddress(request);
        int length = integer(request, "length", 256, 1, MAX_MEMORY);
        byte[] bytes = new byte[length];
        int read = currentProgram.getMemory().getBytes(start, bytes);
        if (read < bytes.length) bytes = java.util.Arrays.copyOf(bytes, read);
        JsonObject result = new JsonObject();
        result.addProperty("address", address(start));
        result.addProperty("length", bytes.length);
        result.addProperty("hex", hex(bytes));
        result.addProperty("base64", Base64.getEncoder().encodeToString(bytes));
        return result;
    }

    private JsonArray searchBytes(JsonObject request) throws Exception {
        String pattern = string(request, "pattern", true);
        return searchPattern(parsePattern(pattern), integer(request, "limit", 100, 1, MAX_LIMIT));
    }

    private JsonArray searchText(JsonObject request) throws Exception {
        String query = string(request, "query", true);
        byte[] bytes = query.getBytes(StandardCharsets.UTF_8);
        int[] pattern = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) pattern[i] = bytes[i] & 0xff;
        return searchPattern(pattern, integer(request, "limit", 100, 1, MAX_LIMIT));
    }

    private int[] parsePattern(String value) {
        String[] tokens = value.trim().split("\\s+");
        if (tokens.length == 0 || tokens.length > 1024) throw new IllegalArgumentException("Invalid byte pattern");
        int[] result = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            if ("?".equals(tokens[i]) || "??".equals(tokens[i])) result[i] = -1;
            else result[i] = Integer.parseInt(tokens[i], 16);
            if (result[i] > 255) throw new IllegalArgumentException("Invalid byte: " + tokens[i]);
        }
        return result;
    }

    private JsonArray searchPattern(int[] pattern, int limit) throws Exception {
        JsonArray result = new JsonArray();
        Memory memory = currentProgram.getMemory();
        long scanned = 0;
        int chunkSize = 64 * 1024;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            long blockSize = Math.min(block.getSize(), MAX_SEARCH - scanned);
            for (long offset = 0; offset < blockSize && result.size() < limit; offset += chunkSize - pattern.length + 1) {
                monitor.checkCancelled();
                int wanted = (int) Math.min(chunkSize, blockSize - offset);
                byte[] chunk = new byte[wanted];
                Address start = block.getStart().add(offset);
                int count = memory.getBytes(start, chunk);
                for (int i = 0; i <= count - pattern.length && result.size() < limit; i++) {
                    boolean match = true;
                    for (int j = 0; j < pattern.length; j++) {
                        if (pattern[j] >= 0 && (chunk[i + j] & 0xff) != pattern[j]) { match = false; break; }
                    }
                    if (match) {
                        JsonObject item = new JsonObject();
                        item.addProperty("address", address(start.add(i)));
                        result.add(item);
                    }
                }
                scanned += count;
                if (scanned >= MAX_SEARCH) break;
            }
            if (result.size() >= limit || scanned >= MAX_SEARCH) break;
        }
        return result;
    }

    private JsonObject analysisOptions() {
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        JsonObject result = new JsonObject();
        for (String name : options.getOptionNames()) result.addProperty(name, options.getValueAsString(name));
        return result;
    }

    private JsonObject setAnalysisOptions(JsonObject request) {
        JsonObject requested = request.getAsJsonObject("options");
        if (requested == null || requested.size() == 0) throw new IllegalArgumentException("options is required");
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (Map.Entry<String, JsonElement> entry : requested.entrySet()) {
            if (!options.contains(entry.getKey())) throw new IllegalArgumentException("Unknown analysis option: " + entry.getKey());
            Object current = options.getObject(entry.getKey(), null);
            String value = entry.getValue().getAsString();
            if (current instanceof Boolean) options.putObject(entry.getKey(), Boolean.parseBoolean(value));
            else if (current instanceof Integer) options.putObject(entry.getKey(), Integer.parseInt(value));
            else if (current instanceof Long) options.putObject(entry.getKey(), Long.parseLong(value));
            else if (current instanceof Float) options.putObject(entry.getKey(), Float.parseFloat(value));
            else if (current instanceof Double) options.putObject(entry.getKey(), Double.parseDouble(value));
            else options.putObject(entry.getKey(), value);
        }
        return analysisOptions();
    }

    private JsonObject continueAnalysis() throws Exception {
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
        JsonObject result = info();
        result.addProperty("analyzed", true);
        return result;
    }

    private JsonObject reanalyze() throws Exception {
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.reAnalyzeAll(currentProgram.getMemory().getLoadedAndInitializedAddressSet());
        manager.startAnalysis(monitor);
        JsonObject result = info();
        result.addProperty("reanalyzed", true);
        return result;
    }

    private JsonObject rename(JsonObject request) throws Exception {
        String value = string(request, "value", true);
        JsonObject result = new JsonObject();
        Function function = tryResolveFunction(request);
        if (function != null) {
            String old = function.getName(true);
            function.setName(value, SourceType.USER_DEFINED);
            if (decompiler != null) decompiler.flushCache();
            result.addProperty("oldName", old);
            result.addProperty("newName", function.getName(true));
            result.addProperty("address", address(function.getEntryPoint()));
            return result;
        }
        Symbol symbol = resolveSymbol(request);
        String old = symbol.getName(true);
        symbol.setName(value, SourceType.USER_DEFINED);
        result.addProperty("oldName", old);
        result.addProperty("newName", symbol.getName(true));
        result.addProperty("address", address(symbol.getAddress()));
        return result;
    }

    private JsonObject comment(JsonObject request) throws Exception {
        Address address = resolveAddress(request);
        String value = string(request, "value", false);
        String kind = string(request, "commentType", false);
        CommentType type = CommentType.valueOf(kind == null ? "EOL" : kind);
        CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(address);
        if (unit == null) throw new IllegalArgumentException("No code or data at " + address);
        String old = unit.getComment(type);
        unit.setComment(type, value);
        JsonObject result = new JsonObject();
        result.addProperty("address", address(unit.getAddress()));
        result.addProperty("type", type.name());
        result.addProperty("oldValue", old);
        result.addProperty("value", value);
        return result;
    }

    private JsonObject patch(JsonObject request) throws Exception {
        Address address = resolveAddress(request);
        byte[] bytes = parseHex(string(request, "bytes", true));
        if (bytes.length == 0 || bytes.length > MAX_MEMORY) throw new IllegalArgumentException("Patch must be 1 to " + MAX_MEMORY + " bytes");
        byte[] old = new byte[bytes.length];
        int read = currentProgram.getMemory().getBytes(address, old);
        if (read != old.length) throw new MemoryAccessException("Could not read complete patch range");
        Address end = address.add(bytes.length - 1L);
        currentProgram.getListing().clearCodeUnits(address, end, false);
        currentProgram.getMemory().setBytes(address, bytes);
        disassemble(address);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
        JsonObject result = new JsonObject();
        result.addProperty("address", address(address));
        result.addProperty("oldBytes", hex(old));
        result.addProperty("bytes", hex(bytes));
        return result;
    }

    private byte[] parseHex(String value) {
        String trimmed = value.trim();
        boolean contiguous = trimmed.matches("(?i)(?:0x)?(?:[0-9a-f]{2})+");
        boolean tokenized = trimmed.matches("(?i)(?:0x)?[0-9a-f]{2}(?:[\\s,:-]+(?:0x)?[0-9a-f]{2})+");
        if (!contiguous && !tokenized) throw new IllegalArgumentException("Hex bytes must be contiguous pairs or complete byte tokens");
        String clean = trimmed.replaceAll("(?i)0x", "").replaceAll("[\\s,:-]", "");
        byte[] result = new byte[clean.length() / 2];
        for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        return result;
    }

    private Function resolveFunction(JsonObject request) throws Exception {
        Function function = tryResolveFunction(request);
        if (function == null) throw new IllegalArgumentException("Function not found; provide a function name or address");
        return function;
    }

    private Function tryResolveFunction(JsonObject request) throws Exception {
        String address = string(request, "address", false);
        if (address != null) {
            Address parsed = parseInputAddress(address);
            Function function = currentProgram.getFunctionManager().getFunctionAt(parsed);
            if (function == null) function = currentProgram.getFunctionManager().getFunctionContaining(parsed);
            return function;
        }
        String name = string(request, "name", false);
        if (name == null) return null;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (name.equals(function.getName()) || name.equals(function.getName(true))) return function;
        }
        FunctionIterator external = currentProgram.getFunctionManager().getExternalFunctions();
        while (external.hasNext()) {
            Function function = external.next();
            if (name.equals(function.getName()) || name.equals(function.getName(true))) return function;
        }
        return null;
    }

    private Symbol resolveSymbol(JsonObject request) throws Exception {
        String address = string(request, "address", false);
        if (address != null) {
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(parseInputAddress(address));
            if (symbol != null) return symbol;
        }
        String name = string(request, "name", false);
        if (name != null) {
            SymbolIterator iterator = currentProgram.getSymbolTable().getSymbols(name);
            if (iterator.hasNext()) return iterator.next();
        }
        throw new IllegalArgumentException("Symbol not found");
    }

    private Address resolveAddress(JsonObject request) throws Exception {
        String value = string(request, "address", false);
        if (value != null) return parseInputAddress(value);
        Function function = tryResolveFunction(request);
        if (function != null) return function.getEntryPoint();
        throw new IllegalArgumentException("address or function name is required");
    }

    private Address parseInputAddress(String value) throws Exception {
        Address result = currentProgram.getAddressFactory().getAddress(value);
        if (result == null && value.startsWith("0x")) result = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.substring(2));
        if (result == null && value.matches("[0-9a-fA-F]+")) result = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        if (result == null) throw new IllegalArgumentException("Invalid address: " + value);
        return result;
    }

    private String string(JsonObject object, String key, boolean required) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            if (required) throw new IllegalArgumentException(key + " is required");
            return null;
        }
        String result = value.getAsString();
        if (required && result.isBlank()) throw new IllegalArgumentException(key + " is required");
        return result;
    }

    private int integer(JsonObject object, String key, int fallback, int minimum, int maximum) {
        JsonElement value = object.get(key);
        int result = value == null || value.isJsonNull() ? fallback : value.getAsInt();
        if (result < minimum || result > maximum) throw new IllegalArgumentException(key + " must be between " + minimum + " and " + maximum);
        return result;
    }

    private boolean has(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull();
    }

    private String address(Address value) {
        return value == null ? null : value.toString();
    }

    private String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
