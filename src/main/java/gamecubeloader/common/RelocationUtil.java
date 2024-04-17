package gamecubeloader.common;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Relocation implementation for ELF PowerPC in the context for Nintendo
 * GameCube and Wii.
 */
public final class RelocationUtil {

    private RelocationUtil() {
        // Don't allow this to be instantiated.
    }

    /**
     * Relocation type: No relocation.
     */
    public static final short R_PPC_NONE = 0;
    /**
     * Relocation type: Full 32-bit (4 bytes) pointer is inserted here.
     */
    public static final short R_PPC_ADDR32 = 1;
    /**
     * Relocation type: lower 24-bit (3 bytes) pointer is inserted here.
     */
    public static final short R_PPC_ADDR24 = 2;
    /**
     * Relocation type: Lower 16-bit of the address is inserted here.
     */
    public static final short R_PPC_ADDR16 = 3;
    /**
     * Relocation type: Lower 16-bit of the address is inserted here.
     */
    public static final short R_PPC_ADDR16_LO = 4;
    /**
     * Relocation type: Upper 16-bit of the address is inserted here.
     */
    public static final short R_PPC_ADDR16_HI = 5;
    /**
     * Relocation type Upper 16-bit of the address plus 0x10000 is inserted here.
     * Used where the lower 16-bit is greater or equal than 0x8000, so a subtract
     * operation is used to load the lower 16-bits.
     */
    public static final short R_PPC_ADDR16_HA = 6;
    /**
     * Relocation type: Lower 16-bits is inserted here.
     */
    public static final short R_PPC_ADDR14 = 7;
    /**
     * Relocation type: Lower 14-bits is inserted here.
     */
    public static final short R_PPC_ADDR14_BRTAKEN = 8;
    /**
     * Relocation type: Lower 14-bits is inserted here.
     */
    public static final short R_PPC_ADDR14_BRNTAKEN = 9;
    /**
     * Relocation type: Insert the difference between the relocation and target
     * address, as 24-bits. Used for branching.
     */
    public static final short R_PPC_REL24 = 10;
    /**
     * Relocation type: Insert the difference between the relocation and target
     * address, as 14-bits. Used for branching.
     */
    public static final short R_PPC_REL14 = 11;
    /**
     * Relocation type: Insert the difference between the relocation and target
     * address, as 14-bits. Used for branching.
     */
    public static final short R_PPC_REL14_BRTAKEN = 12;
    /**
     * Relocation type: Insert the difference between the relocation and target
     * address, as 14-bits. Used for branching.
     */
    public static final short R_PPC_REL14_BRNTAKEN = 13;
    /**
     * Relocation type: Do nothing, used to advance the offset by more than 64ki
     * bytes.
     */
    public static final short R_DOLPHIN_NOP = 201;
    /**
     * Relocation type: Changes the section to relocate from to the specified id.
     * The internal offset is reset to 0.
     */
    public static final short R_DOLPHIN_SECTION = 202;
    /**
     * Relocation type: End of the relocation table.
     */
    public static final short R_DOLPHIN_END = 203;
    public static final short R_DOLPHIN_MRKREF = 204;

    /**
     * Returns whenever the relocation type is a valid known relocation type. Those
     * starts with {@code R_PPC_}. It does not detect Dolphin extended relocation
     * types, use {@link #isDolphinExtension(int)} to check for those.
     *
     * @param relocationType The relocation type to check.
     * @return {@code true} when the relocation type is valid, {@code false}
     *         otherwise.
     * @see #isDolphinExtension(int)
     */
    public static boolean isValid(int relocationType) {
        switch (relocationType) {
        case R_PPC_NONE:
        case R_PPC_ADDR32:
        case R_PPC_ADDR24:
        case R_PPC_ADDR16:
        case R_PPC_ADDR16_LO:
        case R_PPC_ADDR16_HI:
        case R_PPC_ADDR16_HA:
        case R_PPC_ADDR14:
        case R_PPC_ADDR14_BRTAKEN:
        case R_PPC_ADDR14_BRNTAKEN:
        case R_PPC_REL24:
        case R_PPC_REL14:
        case R_PPC_REL14_BRTAKEN:
        case R_PPC_REL14_BRNTAKEN:
            return true;
        default:
            return false;
        }
    }

    /**
     * Returns whenever the relocation type is an Dolphin extension. Those starts
     * with {@code R_DOLPHIN_}. It does not detect standard relocation types, use
     * {@link #isValid(int)} to check for those.
     *
     * @param relocationType The relocation type to check.
     * @return {@code true} when the relocation type is an valid Dolphin extended
     *         one, {@code false} otherwise.
     * @see #isValid(int)
     */
    public static boolean isDolphinExtension(int relocationType) {
        switch (relocationType) {
        case R_DOLPHIN_NOP:
        case R_DOLPHIN_SECTION:
        case R_DOLPHIN_END:
        case R_DOLPHIN_MRKREF:
            return true;
        default:
            return false;
        }
    }

    /**
     * Returns the size of the relocation type. The size is the amount of bytes to
     * modify at the specified relocation address. This can be used to make a
     * snapshot of the previous bytes before applying the relocation.
     *
     * @param relocationType The relocation type to check.
     * @return {@code 0} when invalid or not appropriate, {@code 2} or {@code 4},
     *         depending on the supported relocation.
     */
    public static int getSize(int relocationType) {
        switch (relocationType) {
        case R_PPC_ADDR32:
        case R_PPC_ADDR24:
            return 4;
        case R_PPC_ADDR16:
        case R_PPC_ADDR16_LO:
        case R_PPC_ADDR16_HI:
        case R_PPC_ADDR16_HA:
            return 2;
        case R_PPC_ADDR14:
        case R_PPC_ADDR14_BRTAKEN:
        case R_PPC_ADDR14_BRNTAKEN:
            return 4;
        case R_PPC_REL24:
        case R_PPC_REL14:
        case R_PPC_REL14_BRTAKEN:
        case R_PPC_REL14_BRNTAKEN:
            return 4;
        default:
            return 0;
        }
    }

    /**
     * Returns whenever the specified relocation type can be applied using
     * {@link #apply(Memory, boolean, Address, Address, int)}.
     *
     * @param relocationType The relocation type to check.
     * @return {@code true} when
     *         {@link #apply(Memory, boolean, Address, Address, int)} supports the
     *         relocation, {@code false} otherwise.
     * @see #apply(Memory, boolean, Address, Address, int)
     * @see #apply(Memory, boolean, Address, long, int)
     */
    public static boolean doesRelocate(int relocationType) {
        return getSize(relocationType) != 0;
    }

    /**
     * Apply a relocation. This modifies the memory at {@code source} to point to
     * the target {@code target} using the specified relocation type.
     *
     * @param memory         The memory to modify the bytes of. {@code target}
     *                       should point into this. It must be non-{@code null}.
     * @param isBigEndian    {@code true} to operate in big endian mode,
     *                       {@code false} to operate in little endian mode.
     * @param source         The memory address inside {@code memory} where the
     *                       relocation takes place. It may be modified if
     *                       successful. It must be non-{@code null}.
     * @param target         The memory address inside {@code memory} that it should
     *                       point to. It isn't modified. It must be
     *                       non-{@code null}.
     * @param relocationType The relocation type, describing how to apply the
     *                       relocation.
     * @return {@code true} whenever the relocation was applied successfully, or
     *         {@code false} otherwise when the relocation type was invalid or
     *         unsupported.
     * @throws MemoryAccessException Whenever there was an error reading the memory
     *                               at {@code source}. Relocation won't be applied.
     * @see #apply(Memory, boolean, Address, long, int)
     * @see #doesRelocate(int)
     */
    public static boolean apply(Memory memory, boolean isBigEndian, Address source, Address target, int relocationType)
            throws MemoryAccessException {
        return apply(memory, isBigEndian, source, target.getOffset(), relocationType);
    }

    /**
     * Apply a relocation. This modifies the memory at {@code source} to point to
     * the target {@code target} using the specified relocation type.
     *
     * @param memory         The memory to modify the bytes of. {@code target}
     *                       should point into this. It must be non-{@code null}.
     * @param isBigEndian    {@code true} to operate in big endian mode,
     *                       {@code false} to operate in little endian mode.
     * @param source         The memory address inside {@code memory} where the
     *                       relocation takes place. It may be modified if
     *                       successful. It must be non-{@code null}.
     * @param target         The memory address inside {@code memory} that it should
     *                       point to. It isn't modified. It must be a positive
     *                       number from {@code 0L} to {@code 0xFFFFFFFFL}, both
     *                       inclusive.
     * @param relocationType The relocation type, describing how to apply the
     *                       relocation.
     * @return {@code true} whenever the relocation was applied successfully, or
     *         {@code false} otherwise when the relocation type was invalid or
     *         unsupported.
     * @throws MemoryAccessException Whenever there was an error reading the memory
     *                               at {@code source}. Relocation won't be applied.
     * @see #apply(Memory, boolean, Address, Address, int)
     * @see #doesRelocate(int)
     */
    public static boolean apply(Memory memory, boolean isBigEndian, Address source, long target, int relocationType)
            throws MemoryAccessException {
        if (source == null || !isValid(relocationType)) {
            return false;
        }

        int size = getSize(relocationType);
        if (size != 2 && size != 4) {
            return false;
        }

        int value;
        if (size == 2) {
            value = memory.getShort(source, isBigEndian);
        } else {
            value = memory.getInt(source, isBigEndian);
        }

        switch (relocationType) {
        case R_PPC_ADDR32:
            memory.setInt(source, (int) (value + target), isBigEndian);
            break;
        case R_PPC_ADDR24:
            memory.setInt(source, (int) ((value & 0xfc000003) | (target & 0x3fffffc)), isBigEndian);
            break;
        case R_PPC_ADDR16:
        case R_PPC_ADDR16_LO:
            memory.setShort(source, (short) (target & 0xffff), isBigEndian);
            break;
        case R_PPC_ADDR16_HI:
            memory.setShort(source, (short) ((target >> 16) & 0xffff), isBigEndian);
            break;
        case R_PPC_ADDR16_HA:
            memory.setShort(source, (short) ((target >> 16) + ((target & 0x8000) != 0 ? 1 : 0) & 0xffff), isBigEndian);
            break;
        case R_PPC_ADDR14:
        case R_PPC_ADDR14_BRTAKEN:
        case R_PPC_ADDR14_BRNTAKEN:
            memory.setInt(source, (int) ((value & 0xffff0003) | (target & 0xfffc)), isBigEndian);
            break;
        case R_PPC_REL24:
            memory.setInt(source, (int) ((value & 0xfc000003) | ((value - target) & 0x3fffffc)), isBigEndian);
            break;
        case R_PPC_REL14:
            memory.setInt(source, (int) ((value & 0xffff0003) | ((value - target) & 0xfffc)), isBigEndian);
            break;
        }
        return true;
    }

}
