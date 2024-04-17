package gamecubeloader.rel;

import java.io.IOException;
import java.util.ArrayList;

import gamecubeloader.common.RelocationUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.util.Msg;

/**
 * Represents an REL file.
 */
public final class REL {

    /**
     * The header itself.
     */
    public Header header;
    /**
     * Section table, containing sections that may or may not be loadable.
     */
    public Section[] sections;
    /**
     * Contains the import table, containing imports.
     */
    public ImportTableEntry[] imports;

    /**
     * The header that the file starts with.
     */
    public final class Header {
        /**
         * Unique ID of the module. Module 0 is reserved for the main game binary.
         */
        public long moduleId;
        /**
         * Previous module in the linked list of modules. This is filled at runtime, it
         * is ignored during linking.
         */
        public long previousModuleAddress;
        /**
         * Next module in the linked list of modules. This is filled at runtime, it is
         * ignored during linking.
         */
        public long nextModuleAddress;
        /**
         * Number of sections. The first section (that is also counted) is always a
         * dummy one (like the one in ELF files).
         *
         * @see #sectionTableOffset
         */
        public long sectionCount;
        /**
         * Where the section table is located in, relative to the beginning of the REL
         * file.
         *
         * @see #sectionCount
         */
        public long sectionTableOffset;
        /**
         * Where the name of this module is located in, relative to an external block of
         * data not inside of a REL file. The length of the name is available at
         * {@link #moduleNameLength}.
         *
         * @see moduleNameLength
         */
        public long moduleNameOffset;
        /**
         * Length of the name of this module.
         *
         * @see moduleNameOffset
         */
        public long moduleNameLength;
        /**
         * Version of the REL file, NOT of the module itself (there is none). Supported
         * are version 1, 2 and 3.
         */
        public long moduleVersion; // REL Version
        /**
         * Size of the BSS section (which is null-initialized and isn't stored in the
         * REL file itself).
         */
        public long bssSize;
        /**
         * Where the relocation of this module is located in, relative to the beginning
         * of the REL file.
         */
        public long relocationTableOffset;
        /**
         * Where the import table of this module is located in, relative to the
         * beginning of the REL file.
         *
         * @see #importTableSize
         */
        public long importTableOffset;
        /**
         * Size of the import table in bytes. Each entry is 8 bytes long, so divide by 8
         * to get the number of import entries.
         *
         * @see #importTableOffset
         * @see #getImportTableCount()
         */
        public long importTableSize;

        /**
         * In which section (by index) the prolog callback is located in. The prolog
         * callback is usually called after linking. If 0, then there is no callback.
         *
         * @see #prologSectionOffset
         * @see #epilogSectionOffset
         */
        public int prologSectionId;
        /**
         * In which section (by index) the epilog callback is located in. The epilog
         * callback is usually called before unlinking. If 0, then there is no callback.
         *
         * @see #epilogSectionOffset
         * @see #prologSectionOffset
         */
        public int epilogSectionId;
        /**
         * In which section (by index) the unresolved callback is located in. The
         * unresolved callback is usually called when there are unresolved relocations.
         * If 0, then there is no callback. TODO: Look where it is really called.
         *
         * @see #unresolvedSectionOffset
         */
        public int unresolvedSectionId;
        /**
         * In which section (by index) the BSS section is represented in.
         * This is filled at runtime and should not be used normally.
         * @see REL#getBSSSection()
         */
        public int bssSectionId;
        /**
         * Where the prolog callback is located, starting from the section specified in
         * {@link #prologSectionId}.
         *
         * @see #prologSectionId
         */
        public long prologSectionOffset;
        /**
         * Where the epilog callback is located, starting from the section specified in
         * {@link #epilogSectionId}.
         *
         * @see #epilogSectionId
         */
        public long epilogSectionOffset;
        /**
         * Where the unresolved callback is located, starting from the section specified
         * in {@link #unresolvedSectionId}.
         *
         * @see #unresolvedSectionId
         */
        public long unresolvedSectionOffset;

        /**
         * What alignment each section should fulfill. Only for REL versions 2 or
         * higher. For REL versions 1 or lower, the default is 32.
         */
        public long sectionAlignment;
        /**
         * What alignment the BSS section should fulfill. Only for REL versions 2 or
         * higher. For REL versions 1 or lower, the default is 32.
         */
        public long bssSectionAlignment;
        /**
         * Offset from the beginning of the REL file where to place the BSS section in.
         * Usually this points to the relocation table, because this isn't needed
         * anymore after linking. Only for REL versions 3 or higher. For REL versions 2
         * or lower, memory way automatically allocated for the BSS section.
         */
        public long fixSize;

        /**
         * Returns the number of entries inside the import table.
         *
         * @return the number of entries inside the import table.
         * @see #importTableSize
         */
        public long getImportTableCount() {
            return this.importTableSize / REL.ImportTableEntry.SIZE;
        }

        public Header(BinaryReader reader) throws IOException {
            this.read(reader);
        }

        private void read(BinaryReader reader) throws IOException {
            reader.setPointerIndex(0);

            this.moduleId = reader.readNextUnsignedInt();
            this.previousModuleAddress = reader.readNextUnsignedInt();
            this.nextModuleAddress = reader.readNextUnsignedInt();
            this.sectionCount = reader.readNextUnsignedInt();
            this.sectionTableOffset = reader.readNextUnsignedInt();
            this.moduleNameOffset = reader.readNextUnsignedInt();
            this.moduleNameLength = reader.readNextUnsignedInt();
            this.moduleVersion = reader.readNextUnsignedInt();
            this.bssSize = reader.readNextUnsignedInt();
            this.relocationTableOffset = reader.readNextUnsignedInt();
            this.importTableOffset = reader.readNextUnsignedInt();
            this.importTableSize = reader.readNextUnsignedInt();
            this.prologSectionId = reader.readNextUnsignedByte();
            this.epilogSectionId = reader.readNextUnsignedByte();
            this.unresolvedSectionId = reader.readNextUnsignedByte();
            this.bssSectionId = reader.readNextUnsignedByte();
            this.prologSectionOffset = reader.readNextUnsignedInt();
            this.epilogSectionOffset = reader.readNextUnsignedInt();
            this.unresolvedSectionOffset = reader.readNextUnsignedInt();

            if (this.moduleVersion > 1) {
                this.sectionAlignment = reader.readNextUnsignedInt();
                this.bssSectionAlignment = reader.readNextUnsignedInt();
            } else {
                // Version 1 default values for alignment
                this.sectionAlignment = 32;
                this.bssSectionAlignment = 32;
            }

            if (this.moduleVersion > 2) {
                this.fixSize = reader.readNextUnsignedInt();
            } else {
                this.fixSize = 0;
            }
        }

        /**
         * Checks various stuff to assert whenever the REL file is actually valid.
         *
         * @param reader The data to read from.
         * @throws InvalidRELException When the REL file is invalid or has
         *                             inconsistencies.
         */
        public void isValid(BinaryReader reader) throws InvalidRELException {
            try {
                long fileSize = reader.length();

                if (this.sectionTableOffset > fileSize) {
                    throw new InvalidRELException("Section Info Table address is past file bounds");
                }

                if (this.sectionTableOffset + this.sectionCount * REL.Section.SIZE > fileSize) {
                    throw new InvalidRELException("Section Info Table runs past file bounds");
                }

                if (this.relocationTableOffset >= fileSize) {
                    throw new InvalidRELException("Relocation Data offset is past the file bounds");
                }

                if (this.importTableOffset + this.importTableSize > fileSize) {
                    throw new InvalidRELException("Import Table offset + Import Table size is past the file bounds");
                }

                if ((this.importTableSize % REL.ImportTableEntry.SIZE) != 0) {
                    throw new InvalidRELException(
                            String.format("Import Table Size is not a multiple of %d", REL.ImportTableEntry.SIZE));
                }

                long sectionTableSize = this.sectionCount * REL.Section.SIZE;

                // Get the first section address by file address.
                long firstSectionInFileAddress = -1;
                reader.setPointerIndex(this.sectionTableOffset);

                for (int i = 0; i < this.sectionCount; i++) {
                    long sectionAddress = reader.readNextUnsignedInt() & ~1; // Clear the executable bit-flag.
                    long sectionSize = reader.readNextUnsignedInt();

                    if (sectionAddress != 0 && sectionSize != 0 && sectionSize != this.bssSize) {
                        if (firstSectionInFileAddress == -1 || sectionAddress < firstSectionInFileAddress) {
                            firstSectionInFileAddress = sectionAddress;
                        }
                    }
                }

                // Ensure that the section table offset doesn't intersect the first section's
                // data.
                if (this.sectionTableOffset + sectionTableSize > firstSectionInFileAddress) {
                    throw new InvalidRELException("Section Info Table intersects section data");
                }

                // TODO: Ensure that no section intersects with another. Should this include the
                // relocation data section & import info section?
            } catch (IOException e) {
                throw new InvalidRELException(e);
            }
        }

        public long getEffectiveModuleVersion() {
            if (this.moduleVersion < 1) {
                return 1L;
            }
            if (this.moduleVersion > 3) {
                return 3;
            }
            return this.moduleVersion;
        }

        public DataType toDataType() {
            Structure struct = new StructureDataType(new CategoryPath("/REL"),
                    String.format("RELHeader%d", getEffectiveModuleVersion()), 0);

            DataType uint8_t = ByteDataType.dataType;
            DataType uint32_t = DWordDataType.dataType;
            DataType ptr = PointerDataType.dataType;

            struct.add(uint32_t, "module_id", "Unique Module ID, 0 is reserved for the main DOL");
            struct.add(uint32_t, "next_module_link", "Doubly linked list of loaded modules, filled at runtime");
            struct.add(uint32_t, "prev_module_link", "Doubly linked list of loaded modules, filled at runtime");
            struct.add(uint32_t, "section_count", "Number of sections, including the first dummy one");
            struct.add(ptr, "section_info_offset", "Pointer to table of sections");
            struct.add(uint32_t, "module_name_offset",
                    "Offset from a dedicated Module Name Block that is the name of this module");
            struct.add(uint32_t, "module_name_length", "Size of the name of this module");
            struct.add(uint32_t, "module_version", "Version of the module file format");
            struct.add(uint32_t, "bss_size", "Size of the BSS section");
            struct.add(uint32_t, "relocation_table_offset", "Pointer to table of relocations");
            struct.add(ptr, "import_table_offset", "Pointer to table of imports");
            struct.add(uint32_t, "import_table_size", "Size in bytes of the import table");
            struct.add(uint8_t, "prolog_section_index", "Section index of the prolog function, 0 if none");
            struct.add(uint8_t, "epilog_section_index", "Section index of the epilog function, 0 if none");
            struct.add(uint8_t, "unresolved_section_index", "Section index of the unresolved function, 0 if none");
            struct.add(uint8_t, "_padding", "Used to store the BSS section at runtime");
            struct.add(uint32_t, "prolog_section_offset", "Offset from the section of the prolog function");
            struct.add(uint32_t, "epilog_section_offset", "Offset from the section of the epilog function");
            struct.add(uint32_t, "unresolved_section_offset", "Offset from the section of the unresolved function");
            if (moduleVersion >= 2) {
                struct.add(uint32_t, "module_alignment", "Alignment of this module data itself");
                struct.add(uint32_t, "bss_alignment", "Alignment of the BSS section");
            }
            if (moduleVersion >= 3) {
                struct.add(uint32_t, "fix_size",
                        "Pointer to an area inside the module that can be re-used as BSS section");
            }

            return struct;
        }

        /**
         * Size of the header. This depends on the REL version, as specified in the
         * header.
         *
         * @return Size of the header in bytes.
         * @see #moduleVersion
         */
        public int size() {
            switch ((int) this.moduleVersion) {
            case 0:
            case 1:
                return 0x40;

            case 2:
                return 0x48;

            case 3:
            default:
                return 0x4C;
            }
        }
    }

    public final class Section {
        /**
         * Size of this structure in bytes.
         */
        public static final long SIZE = 8;

        /**
         * Offset from the beginning of the REL to the contents of this section. If 0,
         * this is the BSS section.
         *
         * @see #size
         */
        public long dataOffset;
        /**
         * Whenever this section contents contains code to be executed.
         */
        public boolean isExecutable;
        /**
         * The size of this section contents.
         *
         * @see #dataOffset
         */
        public long size;

        /**
         * Returns whenever this section represents a BSS section.
         *
         * @return whenever this section represents a BSS section.
         */
        public boolean isBSS() {
            return this.dataOffset == 0 && this.size != 0;
        }

        /**
         * Returns whenever this section contains no data (offset and size both are 0).
         *
         * @return whenever this section is useless.
         */
        public boolean isUseless() {
            return this.dataOffset == 0 && this.size == 0;
        }

        public Section(BinaryReader reader) throws IOException {
            read(reader);
        }

        private void read(BinaryReader reader) throws IOException {
            long rawOffset = reader.readNextUnsignedInt();
            this.dataOffset = rawOffset & ~1;
            this.isExecutable = (rawOffset & 1) != 0;
            this.size = reader.readNextUnsignedInt();
        }

        public DataType toDataType() {
            Structure struct = new StructureDataType(new CategoryPath("/REL"), "Section", 0);

            DataType uint32_t = DWordDataType.dataType;
            DataType b = BooleanDataType.dataType;

            try {
                struct.insertBitFieldAt(0, 4, 0, b, 1, "is_executable",
                        "Whenever this section is intended to be executed");
                struct.insertBitFieldAt(0, 4, 1, uint32_t, 31, "data_offset",
                        "Offset to the actual contents of the section");
                throw new InvalidDataTypeException("I don't know how this is supposed to work");
            } catch (InvalidDataTypeException e) {
                Msg.error(this, "Failed to add bitfield for REL.Section.toDataType", e);
                struct.add(uint32_t, "data_offset_is_executable",
                        "Offset to the actual contents, & 1 for an executable flag");
            }
            struct.add(uint32_t, "size", "Size of this section in bytes");

            return struct;
        }
    }

    /**
     * An import entry describes what to patch (relocate) in this module with
     * addresses to the specified module. That module might be itself to relocate
     * pointers to itself.
     */
    public class ImportTableEntry implements StructConverter {
        /**
         * Size of this structure in bytes.
         */
        public static final long SIZE = 8;

        /**
         * The module id of the module that the relocations will point to. If 0, then
         * this points to the main executable. This may be the module ID itself to
         * relocate itself.
         */
        public long moduleId;

        /**
         * Offset from the beginning of this REL file to a array of relocations to
         * apply.
         */
        public long relocationOffset;

        public ImportTableEntry(BinaryReader reader) throws IOException {
            read(reader);
        }

        private void read(BinaryReader reader) throws IOException {
            this.moduleId = reader.readNextUnsignedInt();
            this.relocationOffset = reader.readNextUnsignedInt();
        }

        public RelocationEntry[] getRelocations(BinaryReader reader) throws IOException {
            ArrayList<RelocationEntry> entries = new ArrayList<>();
            RelocationEntry entry = null;
            reader.setPointerIndex(this.relocationOffset);
            do {
                entry = new RelocationEntry(reader);
                entries.add(entry);
            } while (entry.relocationType != RelocationUtil.R_DOLPHIN_END);
            return entries.toArray(new RelocationEntry[0]);
        }

        public DataType toDataType() {
            Structure struct = new StructureDataType(new CategoryPath("/REL"), "ImportTableEntry", 0);

            DataType uint32_t = DWordDataType.dataType;
            DataType ptr = PointerDataType.dataType;

            struct.add(uint32_t, "module_id", "Module the symbol offset comes from");
            struct.add(ptr, "relocation_offset", "Pointer to list of relications");

            return struct;
        }
    }

    public final class RelocationEntry {
        /**
         * Size of this structure in bytes.
         */
        public static final long SIZE = 8;

        /**
         * Offset from the previous offset to start the relocation on.
         */
        public int offset;
        /**
         * The type of relocation. When this is {@link REL#R_DOLPHIN_END}, then the
         * relocation process ends.
         *
         * @see REL#R_DOLPHIN_END
         */
        public int relocationType;
        /**
         * Target section index that the relocation should resolve to.
         *
         * @see #symbolOffset
         */
        public int symbolSection;
        /**
         * Target address that the relocation should resolve to.
         *
         * @see #symbolSection
         */
        public long symbolOffset;

        public RelocationEntry(BinaryReader reader) throws IOException {
            read(reader);
        }

        private void read(BinaryReader reader) throws IOException {
            this.offset = reader.readNextUnsignedShort();
            this.relocationType = reader.readNextUnsignedByte();
            this.symbolSection = reader.readNextUnsignedByte();
            this.symbolOffset = reader.readNextUnsignedInt();
        }

        public DataType toDataType() {
            Structure struct = new StructureDataType(new CategoryPath("/REL"), "RelocationEntry", 0);

            DataType uint8_t = ByteDataType.dataType;
            DataType uint16_t = WordDataType.dataType;
            DataType ptr = PointerDataType.dataType;

            struct.add(uint16_t, "offset", "Offset from the last source location");
            struct.add(uint8_t, "relocation_type", "Relocation type");
            struct.add(uint8_t, "symbol_section", "Target section index");
            struct.add(ptr, "symbol_offset", "Target section offset");

            return struct;
        }
    }

    public REL(BinaryReader reader) throws InvalidRELException {
        read(reader);
    }

    public void read(BinaryReader reader) throws InvalidRELException {
        try {
            this.header = new Header(reader);
        } catch (Exception e) {
            throw new InvalidRELException("Failed to parse header", e);
        }
        this.header.isValid(reader); // Throws exception
        try {
            ArrayList<Section> sections = new ArrayList<>();
            reader.setPointerIndex(this.header.sectionTableOffset);
            for (int i = 0; i < this.header.sectionCount; ++i) {
                sections.add(i, this.new Section(reader));
            }
            this.sections = sections.toArray(new Section[0]);
        } catch (Exception e) {
            throw new InvalidRELException("Failed to parse section table", e);
        }
        try {
            ArrayList<ImportTableEntry> imports = new ArrayList<>();
            reader.setPointerIndex(this.header.importTableOffset);
            for (int i = 0; i < this.header.importTableSize / ImportTableEntry.SIZE; ++i) {
                imports.add(i, this.new ImportTableEntry(reader));
            }
            this.imports = imports.toArray(new ImportTableEntry[0]);
        } catch (Exception e) {
            throw new InvalidRELException("Failed to parse import table", e);
        }
    }

    /**
     * Returns the section representing BSS if there is one.
     *
     * @return {@code null} when there is no BSS section, otherwise the BSS section.
     */
    public Section getBSSSection() {
        for (Section section : this.sections) {
            if (section.isBSS()) {
                return section;
            }
        }
        return null;
    }

    /**
     * Returns the section representing BSS if there is one.
     *
     * @return {@code 0} when there is no BSS section, otherwise the BSS section index.
     */
    public int getBSSSectionIndex() {
        for (int i = 1; i < sections.length; i++) {
            if (sections[i].isBSS())
                return i;
        }
        return 0;
    }

}
