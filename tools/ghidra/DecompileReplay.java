// Decompile the 13.0.5 replay-save cluster. Offsets are from the NSO image base.
// @category Nintendo Switch

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileReplay extends GhidraScript {
    private static final long[] OFFSETS = {
        0x143c590L,
        0x143d030L,
        0x143d5d0L,
        0x143e580L,
        0x143e850L,
        0x143ea40L,
        0x3721b50L,
        0x37222b0L,
        0x3722fe0L,
        0x1974710L,
    };

    @Override
    public void run() throws Exception {
        Address image = currentProgram.getImageBase();
        println("image " + image);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (long off : OFFSETS) {
            Address addr = image.add(off);
            println("\n======== off 0x" + Long.toHexString(off) + " " + addr + " ========");
            if (getInstructionAt(addr) == null) {
                disassemble(addr);
            }
            Function func = getFunctionAt(addr);
            if (func == null) {
                func = createFunction(addr, "replay_" + Long.toHexString(off));
            }
            if (func == null) {
                println("no function");
                continue;
            }
            println("function " + func.getName() + " entry " + func.getEntryPoint()
                + " body " + func.getBody().getMinAddress() + ".." + func.getBody().getMaxAddress());
            DecompileResults res = decomp.decompileFunction(func, 90, monitor);
            if (!res.decompileCompleted()) {
                println("decompile failed: " + res.getErrorMessage());
                continue;
            }
            println(res.getDecompiledFunction().getSignature());
            println(res.getDecompiledFunction().getC());
        }
        decomp.dispose();
    }
}
