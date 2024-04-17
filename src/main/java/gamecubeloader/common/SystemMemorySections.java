package gamecubeloader.common;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Utility class to create common GameCube & Wii related sections.
 */
public final class SystemMemorySections {

    public static final long ADDR_OSGLOBALS = 0x80000000L;
    public static final int SIZE_OSGLOBALS = 0x3100;

    public static final long ADDR_CP = 0xCC000000L;
    public static final long ADDR_PE = 0xCC001000L;
    public static final long ADDR_VI = 0xCC002000;
    public static final long ADDR_PI = 0xCC003000;
    public static final long ADDR_MI = 0xCC004000;
    public static final long ADDR_DSP = 0xCC005000;
    public static final long ADDR_DI = 0xCC006000;
    public static final long ADDR_SI = 0xCC006400;
    public static final long ADDR_EXI = 0xCC006800;
    public static final long ADDR_AI = 0xCC006C00;
    public static final long ADDR_GFXFIFO = 0xCC008000;

    public static void Create(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {
        createOSGlobals(provider, program, monitor, log);
        createHardware(program, monitor, log);
    }

    /**
     * Creates an memory memory block representing OSGlobals, where Nintendos
     * "Operating System" stores some common data at specific memory addresses.
     * 
     * @param provider Raw Memory Dump data, only used when an block already exists
     *                 at the location.
     * @param program  The program to add the block to. Non-{@code null}.
     * @param monitor  To set a message indicating what we are doing. May be
     *                 {@code null}.
     * @param log      To append log messages while creating the memory block.
     */
    public static void createOSGlobals(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {
        if (monitor != null)
            monitor.setMessage("Creating OSGlobals area...");
        var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        // Create OS globals section. Check if we have the data, otherwise create
        // uninitialized block.
        if (program.getMinAddress().compareTo(addressSpace.getAddress(ADDR_OSGLOBALS)) <= 0) {
            // We have all the OS globals data, likely from a RAM dump.
            try {
                MemoryBlockUtils.createInitializedBlock(program, true, "OSGlobals",
                        addressSpace.getAddress(ADDR_OSGLOBALS), provider.getInputStream(0), SIZE_OSGLOBALS,
                        "Operating System Globals", null, true, true, true, null, monitor);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            // Only mark as overlay if any part of the data already exists.
            final boolean overlay = program.getMinAddress().compareTo(addressSpace.getAddress(ADDR_OSGLOBALS)) < 0;
            MemoryBlockUtils.createUninitializedBlock(program, overlay, "OSGlobals",
                    addressSpace.getAddress(ADDR_OSGLOBALS), SIZE_OSGLOBALS, "Operating System Globals", null, true,
                    true, false, log);
        }
    }

    /**
     * Create memory blocks where hardware registers are located in.
     * 
     * @param program The program to add the block to. Non-{@code null}.
     * @param monitor To set a message indicating what we are doing. May be
     *                {@code null}.
     * @param log     To append log messages while creating the memory block.
     */
    public static void createHardware(Program program, TaskMonitor monitor, MessageLog log) {
        if (monitor != null)
            monitor.setMessage("Creating Hardware areas...");
        createHardwareBlock(program, "CP", ADDR_CP, 0x80, "Command Processor Register", log);
        createHardwareBlock(program, "PE", ADDR_PE, 0x100, "Pixel Engine Register", log);
        createHardwareBlock(program, "VI", ADDR_VI, 0x100, "Video Interface Register", log);
        createHardwareBlock(program, "PI", ADDR_PI, 0x100, "Processor Interface Register", log);
        createHardwareBlock(program, "MI", ADDR_MI, 0x80, "Memory Interface Register", log);
        createHardwareBlock(program, "DSP", ADDR_DSP, 0x200, "Digital Signal Processor Register", log);
        createHardwareBlock(program, "DI", ADDR_DI, 0x40, "DVD Interface Register", log);
        createHardwareBlock(program, "SI", ADDR_SI, 0x100, "Serial Interface Register", log);
        createHardwareBlock(program, "EXX", ADDR_EXI, 0x40, "External Interface Register", log);
        createHardwareBlock(program, "AI", ADDR_AI, 0x40, "Audio Interface Register", log);
        createHardwareBlock(program, "GXFIFO", ADDR_GFXFIFO, 0x8, "Graphics FIFO Register", log);

    }

    /**
     * Quick way to create volatile memory blocks for hardware registers.
     * 
     * @param program The program to add the block to.
     * @param name    The name of the memory block.
     * @param address The address of the memory block.
     * @param length  The length in bytes of the memory block.
     * @param comment A comment for the memory block. May be {@code null}.
     * @param log     To append log messages while creating the memory block.
     * @return
     */
    private static MemoryBlock createHardwareBlock(Program program, String name, long address, long length,
            String comment, MessageLog log) {
        MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
                program.getAddressFactory().getDefaultAddressSpace().getAddress(address), length, comment, null, true,
                true, false, log);
        block.setVolatile(true);
        return block;
    }
}
