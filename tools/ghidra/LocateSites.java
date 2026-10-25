// Print the function and a short disassembly at each .text offset.
// Offsets are relative to the program image base (NSO .text starts there).
// @category Nintendo Switch
//
// Usage: -postScript LocateSites.java 0x38ffcd4 0x38fee44

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;

public class LocateSites extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: LocateSites <text-offset> ...");
            return;
        }
        Address image = currentProgram.getImageBase();
        println("==== " + currentProgram.getName() + " image " + image + " ====");
        for (String arg : args) {
            long off = Long.parseLong(arg.replace("0x", "").replace("0X", ""), 16);
            Address addr = image.add(off);
            Function func = getFunctionContaining(addr);
            Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(addr);
            String funcName = func == null ? "(no function)" : func.getName(true);
            String entry = func == null ? "" : " entry " + func.getEntryPoint();
            String exact = sym == null ? "" : " symbol " + sym.getName(true);
            println(String.format("off 0x%x  %s  %s%s%s", off, addr, funcName, entry, exact));
            Address cursor = addr;
            for (int i = 0; i < 12 && cursor != null; i++) {
                Instruction insn = getInstructionAt(cursor);
                if (insn == null) {
                    disassemble(cursor);
                    insn = getInstructionAt(cursor);
                }
                if (insn == null) {
                    println("  " + cursor + "  <no instruction>");
                    break;
                }
                println("  " + insn.getAddress() + "  " + insn);
                if ("ret".equals(insn.getMnemonicString())) {
                    break;
                }
                cursor = insn.getFallThrough();
                if (cursor == null) {
                    cursor = insn.getAddress().add(insn.getLength());
                }
            }
        }
    }
}
