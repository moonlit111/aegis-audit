// Export actual Ghidra analysis; this script never executes the imported target.
// @category AegisAudit
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportProgram extends HeadlessScript {
    private static String address(Address address) {
        return address == null ? "" : "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }
    private static JsonObject object() { return new JsonObject(); }

    // Common words used to reject "printable by accident" machine data after decoding.
    private static final Set<String> COMMON_WORDS = new HashSet<>(Arrays.asList(
        "the", "and", "for", "with", "this", "that", "from", "have", "not", "are", "was", "but",
        "you", "all", "can", "one", "our", "out", "get", "has", "his", "how", "new", "now", "see",
        "way", "who", "did", "its", "let", "put", "say", "she", "too", "use", "they", "will",
        "your", "what", "when", "where", "which", "while", "about", "after", "again", "because",
        "before", "being", "between", "during", "each", "more", "most", "other", "some", "such",
        "than", "their", "them", "then", "there", "these", "those", "through", "under", "until",
        "very", "were", "would", "should", "could", "is", "it", "to", "of", "in", "on", "at",
        "by", "or", "as", "be", "do", "if", "no", "so", "up", "we", "an", "my", "me", "he", "us",
        "am", "string", "table", "host", "port", "user", "password", "connection", "message",
        "hidden", "fixture", "server", "token", "secret", "error", "file", "path", "name",
        "value", "true", "false", "null", "none", "read", "write", "open", "close", "send",
        "load", "save"));

    private static int commonWords(String text) {
        Set<String> seen = new HashSet<>();
        for (String word : text.toLowerCase().split("[^a-z]+")) {
            if (COMMON_WORDS.contains(word)) seen.add(word);
        }
        return seen.size();
    }

    // Decode a constant-XOR byte table read from program memory; stop at the first
    // non-printable byte so the recorded text stays evidence, not a guess.
    private String decodeXorString(Address dataAddress, int key) {
        byte[] buffer = new byte[8192];
        int read;
        try { read = currentProgram.getMemory().getBytes(dataAddress, buffer); }
        catch (MemoryAccessException error) { return null; }
        if (read <= 0) return null;
        StringBuilder text = new StringBuilder();
        for (int index = 0; index < read; index++) {
            int decoded = (buffer[index] ^ key) & 0xff;
            if (decoded < 0x20 || decoded > 0x7e) break;
            text.append((char) decoded);
        }
        return text.toString();
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("ExportProgram.java <output.json> <snapshot-relative-path>");
        JsonObject root = object();
        root.addProperty("schema_version", 1);
        JsonArray units = new JsonArray(), edges = new JsonArray(), warnings = new JsonArray();
        JsonArray deobfuscation = new JsonArray();
        Set<String> deobfuscatedKeys = new HashSet<>();
        List<String> deobfuscatedTexts = new ArrayList<>();
        boolean analysisTimedOut = analysisTimeoutOccurred();
        if (analysisTimedOut) warnings.add("Ghidra 自动分析达到时限；只保留已恢复的结构，覆盖可能不完整");
        JsonArray files = new JsonArray();
        Set<String> exported = new HashSet<>();
        int total = currentProgram.getFunctionManager().getFunctionCount();
        int count = 0, failed = 0;
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                if (count >= 5000) { warnings.add("函数数超过本轮导出上限 5000，后续函数未分析"); break; }
                Function function = functions.next();
                String key = address(function.getEntryPoint());
                exported.add(key);
                println("AEGIS_FUNCTION " + (++count) + "/" + total + " " + function.getName());
                DecompileResults result = decompiler.decompileFunction(function, 20, monitor);
                boolean ok = result.decompileCompleted() && result.getDecompiledFunction() != null;
                String code = ok ? result.getDecompiledFunction().getC() : "";
                if (!ok) failed++;
                JsonObject unit = object();
                unit.addProperty("key", key);
                unit.addProperty("name", function.getName());
                unit.addProperty("path", args[1]);
                unit.addProperty("language", "binary");
                unit.addProperty("address", key);
                unit.addProperty("start_line", 1);
                unit.addProperty("end_line", Math.max(1, code.split("\n", -1).length));
                unit.addProperty("start_byte", 0);
                unit.addProperty("end_byte", 0);
                unit.addProperty("code", code);
                unit.addProperty("quality", ok ? "PARSED" : "FAILED");
                JsonObject metadata = object();
                metadata.addProperty("kind", "function");
                metadata.addProperty("signature", function.getSignature().toString());
                metadata.addProperty("decompile_error", ok ? "" : result.getErrorMessage());
                metadata.addProperty("image_base", address(currentProgram.getImageBase()));
                metadata.addProperty("rva", "0x" + Long.toUnsignedString(function.getEntryPoint().getOffset() - currentProgram.getImageBase().getOffset(), 16));
                metadata.addProperty("pseudocode_mapping", "FUNCTION_LEVEL_ONLY");
                JsonArray blocks = new JsonArray();
                BasicBlockModel model = new BasicBlockModel(currentProgram);
                CodeBlockIterator blockIterator = model.getCodeBlocksContaining(function.getBody(), monitor);
                int blockCount = 0;
                while (blockIterator.hasNext() && blockCount++ < 1024) {
                    CodeBlock block = blockIterator.next();
                    JsonObject b = object();
                    b.addProperty("start", address(block.getMinAddress()));
                    b.addProperty("end", address(block.getMaxAddress()));
                    JsonArray destinations = new JsonArray();
                    CodeBlockReferenceIterator refs = block.getDestinations(monitor);
                    while (refs.hasNext()) {
                        CodeBlockReference ref = refs.next();
                        JsonObject r = object();
                        r.addProperty("address", address(ref.getDestinationAddress()));
                        r.addProperty("flow_type", ref.getFlowType().toString());
                        destinations.add(r);
                    }
                    b.add("successors", destinations); blocks.add(b);
                }
                metadata.add("basic_blocks", blocks);
                metadata.addProperty("blocks_truncated", blockIterator.hasNext());
                JsonArray pcode = new JsonArray();
                if (ok && result.getHighFunction() != null) {
                    Iterator<PcodeOpAST> ops = result.getHighFunction().getPcodeOps();
                    int n = 0;
                    while (ops.hasNext() && n++ < 512) {
                        PcodeOpAST op = ops.next(); JsonObject operation = object();
                        operation.addProperty("opcode", op.getMnemonic());
                        operation.addProperty("address", address(op.getSeqnum().getTarget()));
                        pcode.add(operation);
                    }
                    metadata.addProperty("pcode_truncated", ops.hasNext());
                }
                metadata.add("pcode", pcode);
                // B06: constant-XOR decode patterns. The decompiler's pointer recovery is
                // unreliable for indexed tables, so combine the constants that appear in the
                // function's XOR instructions with the initialized data addresses the function
                // actually references, then verify the decoded text.
                Set<Integer> xorKeys = new TreeSet<>();
                Set<Address> dataReferences = new LinkedHashSet<>();
                InstructionIterator scanInstructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (scanInstructions.hasNext()) {
                    Instruction instruction = scanInstructions.next();
                    if (instruction.getMnemonicString().toUpperCase().startsWith("XOR")) {
                        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                            for (Object piece : instruction.getOpObjects(operand)) {
                                if (piece instanceof Scalar) {
                                    long value = ((Scalar) piece).getUnsignedValue();
                                    if (value > 0 && value <= 0xff) xorKeys.add((int) value);
                                }
                            }
                        }
                    }
                    for (Reference ref : instruction.getReferencesFrom()) {
                        if (ref.getReferenceType().isCall()) continue;
                        Address to = ref.getToAddress();
                        MemoryBlock block = currentProgram.getMemory().getBlock(to);
                        if (block != null && block.isInitialized()) dataReferences.add(to);
                    }
                }
                for (int xorKey : xorKeys) {
                    for (Address dataAddress : dataReferences) {
                        if (deobfuscatedKeys.size() >= 64) break;
                        String recoveredText = decodeXorString(dataAddress, xorKey);
                        if (recoveredText == null || recoveredText.length() < 8) continue;
                        if (commonWords(recoveredText) < 2) continue;
                        String unique = dataAddress + ":" + xorKey;
                        if (deobfuscatedKeys.contains(unique)) continue;
                        if (deobfuscatedTexts.stream().anyMatch(existing -> existing.contains(recoveredText))) continue;
                        deobfuscatedKeys.add(unique);
                        deobfuscatedTexts.add(recoveredText);
                        JsonObject entry = object();
                        entry.addProperty("kind", "XOR_SINGLE_BYTE");
                        entry.addProperty("function", function.getName());
                        entry.addProperty("function_entry", key);
                        entry.addProperty("data_address", address(dataAddress));
                        entry.addProperty("data_rva", "0x" + Long.toUnsignedString(dataAddress.getOffset() - currentProgram.getImageBase().getOffset(), 16));
                        entry.addProperty("key", String.format("0x%02x", xorKey));
                        entry.addProperty("length", recoveredText.length());
                        entry.addProperty("text", recoveredText.substring(0, Math.min(2000, recoveredText.length())));
                        JsonArray uses = new JsonArray();
                        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(dataAddress)) {
                            if (uses.size() >= 16) break;
                            uses.add(address(ref.getFromAddress()));
                        }
                        entry.add("use_sites", uses);
                        deobfuscation.add(entry);
                    }
                }
                JsonArray strings = new JsonArray();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next(); boolean hasCall = false;
                    for (Reference ref : instruction.getReferencesFrom()) {
                        if (ref.getReferenceType().isCall()) {
                            hasCall = true;
                            Function target = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                            JsonObject edge = object();
                            edge.addProperty("source_key", key);
                            edge.addProperty("target_key", target == null ? "" : address(target.getEntryPoint()));
                            edge.addProperty("target_name", target == null ? address(ref.getToAddress()) : target.getName());
                            edge.addProperty("kind", "CALL");
                            edge.addProperty("certainty", "TOOL_REPORTED");
                            edge.addProperty("address", address(instruction.getAddress()));
                            edge.addProperty("line", 0);
                            edges.add(edge);
                        }
                        Data data = currentProgram.getListing().getDefinedDataAt(ref.getToAddress());
                        if (strings.size() < 64 && data != null && data.getValue() instanceof String) {
                            String value = (String)data.getValue(); JsonObject string = object();
                            string.addProperty("address", address(data.getAddress()));
                            string.addProperty("value", value.substring(0, Math.min(4096, value.length())));
                            strings.add(string);
                        }
                    }
                    if (instruction.getFlowType().isCall() && !hasCall) {
                        JsonObject edge = object();
                        edge.addProperty("source_key", key); edge.addProperty("target_key", "");
                        edge.addProperty("target_name", "indirect call"); edge.addProperty("kind", "CALL");
                        edge.addProperty("certainty", "UNKNOWN"); edge.addProperty("line", 0);
                        edge.addProperty("address", address(instruction.getAddress())); edges.add(edge);
                    }
                }
                metadata.add("referenced_strings", strings);
                unit.add("metadata", metadata); units.add(unit);
            }
        } finally { decompiler.dispose(); }
        for (JsonElement element : edges) {
            JsonObject edge = element.getAsJsonObject();
            if (!exported.contains(edge.get("target_key").getAsString())) edge.addProperty("target_key", "");
        }
        if (count == 0) warnings.add("没有识别出可导出的函数");
        JsonObject file = object();
        file.addProperty("path", args[1]); file.addProperty("language", "binary");
        file.addProperty("status", count == 0 ? "FAILED" : failed > 0 || warnings.size() > 0 ? "PARTIAL" : "PARSED");
        file.addProperty("reason", failed == 0 ? "" : failed + " 个函数反编译失败");
        file.addProperty("unit_count", count); files.add(file);
        JsonObject metadata = object();
        metadata.addProperty("analysis_scope", "STRUCTURE_ANALYSIS");
        metadata.addProperty("ghidra_version", Application.getApplicationVersion());
        metadata.addProperty("analysis_timed_out", analysisTimedOut);
        metadata.addProperty("function_count", count); metadata.addProperty("decompile_failures", failed);
        metadata.addProperty("language_id", currentProgram.getLanguageID().toString());
        metadata.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        metadata.addProperty("call_graph_complete", false);
        metadata.addProperty("vulnerability_audit", "NOT_RUN"); metadata.addProperty("verification", "NOT_RUN");
        root.add("units", units); root.add("edges", edges); root.add("files", files);
        root.add("deobfuscation", deobfuscation);
        root.add("tools", new JsonArray()); root.add("warnings", warnings); root.add("metadata", metadata);
        Files.writeString(Path.of(args[0]), new GsonBuilder().setPrettyPrinting().create().toJson(root), StandardCharsets.UTF_8);
        println("AEGIS_EXPORT_COMPLETE " + count + " functions, " + failed + " failures");
    }
}
