package gamecubeloader.rel;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import gamecubeloader.common.RelocationUtil;
import gamecubeloader.rel.REL.ImportTableEntry;
import gamecubeloader.rel.REL.RelocationEntry;
import gamecubeloader.rel.REL.Section;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class RELLoader extends AbstractLibrarySupportLoader {

    public static final String PROGRAM_INFO_REL_BASE_ADDR = "REL %d Base Address";
    public static final String PROGRAM_INFO_MAIN_MODULE_ID = "OSModule Main ID";

    @Override
    public String getName() {
        return "Nintendo GameCube/Wii Relocatable Module";
    }

    private static long align(long address, long alignment) {
        if ((address % alignment) == 0) {
            return address;
        }
        return address + (alignment - (address % alignment));
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        String monitorPrefix = String.format("[%s] ", provider.getName());

        monitor.initialize(0, monitorPrefix + "Reading REL file...");
        monitor.setIndeterminate(true);
        BinaryReader reader = new BinaryReader(provider, false);
        REL rel;
        try {
            rel = new REL(reader);
        } catch (InvalidRELException e) {
            throw new IOException(e);
        }

        boolean importHeader = true;
        boolean importSectionTable = true;
        boolean importImportTable = true;
        boolean importRelocations = true;
        monitor.initialize(0, monitorPrefix + "Importing header...");
        monitor.setIndeterminate(true);
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        boolean isStandalone = true; // !loadIntoProgram replacement
        long base = OPTION_BASE_ADDR_DEFAULT;
        for (Option option : options) {
            if (option.getName() == OPTION_BASE_ADDR) {
                Object value = option.getValue();
                if (value instanceof Address) {
                    base = ((Address) value).getOffset();
                }
            } else if (option.getName() == OPTION_STANDALONE) {
                Object value = option.getValue();
                if (value instanceof Boolean) {
                    isStandalone = ((Boolean) value).booleanValue();
                }
            } else if (option.getName() == OPTION_IMPORT_HEADER) {
                Object value = option.getValue();
                if (value instanceof Boolean) {
                    importHeader = ((Boolean) value).booleanValue();
                }
            } else if (option.getName() == OPTION_IMPORT_SECTION_TABLE) {
                Object value = option.getValue();
                if (value instanceof Boolean) {
                    importSectionTable = ((Boolean) value).booleanValue();
                }
            } else if (option.getName() == OPTION_IMPORT_IMPORT_TABLE) {
                Object value = option.getValue();
                if (value instanceof Boolean) {
                    importImportTable = ((Boolean) value).booleanValue();
                }
            } else if (option.getName() == OPTION_IMPORT_RELOCATIONS) {
                Object value = option.getValue();
                if (value instanceof Boolean) {
                    importRelocations = ((Boolean) value).booleanValue();
                }
            }
        }
        Address baseAddress = addressSpace.getAddress(base);
        Address baseBSS = addressSpace.getAddress(RELLoader.align(base + provider.length(), rel.header.bssSectionAlignment));
        String namePrefix = String.format("rel%d", rel.header.moduleId);

        if (isStandalone) {
            try {
                // Default to 0x80000000 because that is the default image base for most (all?)
                // GC/Wii software
                program.setImageBase(addressSpace.getAddress(0x80000000L), true);
            } catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) {
                log.appendException(e);
            }
        }

        ReferenceManager reference = program.getReferenceManager();
        if (importHeader) {
            try {
                Address headerAddress = baseAddress;
                MemoryBlockUtils.createInitializedBlock(program, false, namePrefix + "header", headerAddress,
                        provider.getInputStream(0), rel.header.size(),
                        String.format("REL %d header", rel.header.moduleId), provider.getName(), true, true, false, log,
                        monitor);

                DataType headerDataType = rel.header.toDataType();
                // Do references before so it is the primary one
                reference.addMemoryReference(headerAddress.add(0x10L), baseAddress.add(rel.header.sectionTableOffset),
                        RefType.DATA, SourceType.ANALYSIS, 0);
                reference.addMemoryReference(headerAddress.add(0x24L),
                        baseAddress.add(rel.header.relocationTableOffset), RefType.DATA, SourceType.ANALYSIS, 0);
                reference.addMemoryReference(headerAddress.add(0x28L), baseAddress.add(rel.header.importTableOffset),
                        RefType.DATA, SourceType.ANALYSIS, 0);
                if (rel.header.prologSectionId != 0 && rel.header.prologSectionId < rel.sections.length
                        && rel.sections[rel.header.prologSectionId].dataOffset != 0L) {
                    reference.addMemoryReference(headerAddress.add(0x34L), baseAddress
                            .add(rel.sections[rel.header.prologSectionId].dataOffset + rel.header.prologSectionOffset),
                            RefType.DATA, SourceType.ANALYSIS, 0);
                }
                if (rel.header.epilogSectionId != 0 && rel.header.epilogSectionId < rel.sections.length
                        && rel.sections[rel.header.epilogSectionId].dataOffset != 0L) {
                    reference.addMemoryReference(headerAddress.add(0x38L), baseAddress
                            .add(rel.sections[rel.header.prologSectionId].dataOffset + rel.header.epilogSectionOffset),
                            RefType.DATA, SourceType.ANALYSIS, 0);
                }
                if (rel.header.unresolvedSectionId != 0 && rel.header.unresolvedSectionId < rel.sections.length
                        && rel.sections[rel.header.unresolvedSectionId].dataOffset != 0L) {
                    reference
                            .addMemoryReference(headerAddress.add(0x3cL),
                                    baseAddress.add(rel.sections[rel.header.unresolvedSectionId].dataOffset
                                            + rel.header.unresolvedSectionOffset),
                                    RefType.DATA, SourceType.ANALYSIS, 0);
                }
                if (rel.header.moduleVersion >= 3 && rel.header.fixSize != 0) {
                    reference.addMemoryReference(headerAddress.add(0x48L), baseAddress.add(rel.header.fixSize),
                            RefType.DATA, SourceType.ANALYSIS, 0);
                }
                DataUtilities.createData(program, headerAddress, headerDataType, -1,
                        DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
            } catch (AddressOverflowException | AddressOutOfBoundsException | CodeUnitInsertionException e) {
                log.appendException(e);
            }
        }

        monitor.setIndeterminate(false);
        monitor.initialize(rel.sections.length, monitorPrefix + "Importing sections...");
        Map<REL.Section, Address> sectionToAddress = new IdentityHashMap<>();
        Map<Integer, Address> sectionIndexToAddress = new HashMap<>();
        int textSectionCounter = 0;
        int dataSectionCounter = 0;
        for (int i = 0; i < rel.sections.length; ++i, monitor.increment()) {
            REL.Section section = rel.sections[i];

            if (section.isUseless()) {
                continue;
            }

            String blockName;
            if (section.isBSS()) {
                blockName = ".bss";
            } else if (section.isExecutable) {
                blockName = String.format(".text%d", textSectionCounter++);
            } else {
                blockName = String.format(".data%d", dataSectionCounter++);
            }
            String comment = String.format("REL %d Section %d", rel.header.moduleId, i);

            if (section.isBSS()) {
                // There could be multiple BSS sections in a REL file, but from my understanding
                // of the OSLink implementation is that they all point to the same area anyway.
                sectionToAddress.put(section, baseBSS);
                sectionIndexToAddress.put(i, baseBSS);
                MemoryBlockUtils.createUninitializedBlock(program, false, namePrefix + blockName, baseBSS,
                        rel.header.bssSize, comment, provider.getName(), true, true, false, log);
            } else {
                Address address = addressSpace.getAddress(base + section.dataOffset);
                sectionToAddress.put(section, address);
                sectionIndexToAddress.put(i, address);
                InputStream sectionContents = provider.getInputStream(section.dataOffset);
                try {
                    MemoryBlockUtils.createInitializedBlock(program, false, namePrefix + blockName, address,
                            sectionContents, section.size, comment, provider.getName(), true, true,
                            section.isExecutable, log, monitor);
                } catch (AddressOverflowException e) {
                    log.appendException(e);
                }
            }
        }

        if (rel.sections.length != 0 && importSectionTable) {
            monitor.initialize(0, monitorPrefix + "Importing Section Table itself...");
            try {
                Address address = addressSpace.getAddress(base + rel.header.sectionTableOffset);
                MemoryBlockUtils.createInitializedBlock(program, false, namePrefix + "sectiontable", address,
                        provider.getInputStream(rel.header.sectionTableOffset),
                        rel.header.sectionCount * REL.Section.SIZE,
                        String.format("REL %d Section Table", rel.header.moduleId), provider.getName(), true, true,
                        false, log, monitor);

                DataType entryDataType = rel.sections[0].toDataType();
                DataType tableDataType = new ArrayDataType(entryDataType, rel.sections.length,
                        entryDataType.getLength());

                // Do references before so it is the primary one
                for (int i = 0; i < rel.sections.length; i++) {
                    Section entry = rel.sections[i];
                    if (entry.isUseless()) {
                        continue;
                    }
                    if (entry.isBSS()) {
                        reference.addMemoryReference(address.add(i * ImportTableEntry.SIZE), baseBSS, RefType.DATA,
                                SourceType.ANALYSIS, 0);

                    } else {
                        reference.addMemoryReference(address.add(i * ImportTableEntry.SIZE),
                                baseAddress.add(entry.dataOffset), RefType.DATA, SourceType.ANALYSIS, 0);

                    }
                }
                DataUtilities.createData(program, address, tableDataType, -1,
                        DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
            } catch (AddressOverflowException | CodeUnitInsertionException e) {
                log.appendException(e);
            }

        }

        if (rel.imports.length != 0 && importImportTable) {
            monitor.initialize(0, monitorPrefix + "Importing Import Table itself...");
            try {
                Address address = addressSpace.getAddress(base + rel.header.importTableOffset);
                MemoryBlockUtils.createInitializedBlock(program, false, namePrefix + "importtable", address,
                        provider.getInputStream(rel.header.importTableOffset), rel.header.importTableSize,
                        String.format("REL %d Import Table", rel.header.moduleId), provider.getName(), true, true,
                        false, log, monitor);

                DataType entryDataType = rel.imports[0].toDataType();
                DataType tableDataType = new ArrayDataType(entryDataType, rel.imports.length,
                        entryDataType.getLength());

                // Do references before so it is the primary one
                for (int i = 0; i < rel.imports.length; i++) {
                    ImportTableEntry importTableEntry = rel.imports[i];
                    reference.addMemoryReference(address.add(i * ImportTableEntry.SIZE + 0x4L),
                            baseAddress.add(importTableEntry.relocationOffset), RefType.DATA, SourceType.ANALYSIS, 0);
                }
                DataUtilities.createData(program, address, tableDataType, -1,
                        DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
            } catch (AddressOverflowException | CodeUnitInsertionException e) {
                log.appendException(e);
            }
        }

        if (rel.header.relocationTableOffset != 0 && rel.imports.length != 0 && importRelocations) {
            monitor.initialize(0, monitorPrefix + "Importing Relocation Table itself...");
            Address relocationMin = baseAddress.add(rel.header.relocationTableOffset);
            Address relocationMax = relocationMin;
            for (REL.ImportTableEntry importEntry : rel.imports) {
                long size = importEntry.getRelocations(reader).length * REL.RelocationEntry.SIZE;
                Address thisMax = baseAddress.add(importEntry.relocationOffset).add(size);
                if (thisMax.compareTo(relocationMax) > 0) {
                    relocationMax = thisMax;
                }
            }
            if (!program.getMemory().intersects(relocationMin, relocationMax)) {
                try {
                    MemoryBlockUtils.createInitializedBlock(program, false, namePrefix + "relocs", relocationMin,
                            provider.getInputStream(rel.header.relocationTableOffset),
                            relocationMax.subtract(relocationMin),
                            String.format("REL %d relocations", rel.header.moduleId), provider.getName(), true, true,
                            false, log, monitor);

                    for (REL.ImportTableEntry importEntry : rel.imports) {
                        var relocs = importEntry.getRelocations(reader);
                        DataType entryDataType = relocs[0].toDataType();
                        DataType tableDataType = new ArrayDataType(entryDataType, relocs.length,
                                entryDataType.getLength());
                        Address address = baseAddress.add(importEntry.relocationOffset);
                        DataUtilities.createData(program, address, tableDataType, -1,
                                DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

                    }
                } catch (AddressOverflowException | IOException | CodeUnitInsertionException e) {
                    log.appendException(e);
                }
            } else {
                log.appendMsg(String.format("Relocation table intersetcs with something (%s, %s)",
                        relocationMin.toString(), relocationMax.toString()));
            }
        } else if (!importRelocations) {
            log.appendMsg("Relocation table doesn't seem to exists to insert");
        }

        for (REL.ImportTableEntry importEntry : rel.imports) {
            if (importEntry.moduleId == rel.header.moduleId || importEntry.moduleId == 0) {
                var relocEntries = importEntry.getRelocations(reader);
                if (importEntry.moduleId == 0) {
                    monitor.initialize(relocEntries.length,
                            monitorPrefix + "Applying relocations towards base image...");
                    processRelocations(program, rel, sectionToAddress, importEntry, importEntry.getRelocations(reader),
                            null, monitor, log);
                } else {
                    monitor.initialize(relocEntries.length, monitorPrefix + "Applying relocations for itself...");
                    processRelocations(program, rel, sectionToAddress, importEntry, importEntry.getRelocations(reader),
                            sectionIndexToAddress, monitor, log);
                }
            }
        }

        monitor.initialize(0, monitorPrefix + "Final steps...");
        processCallback(program, rel, sectionIndexToAddress, rel.header.prologSectionId, rel.header.prologSectionOffset,
                "prolog", log);
        processCallback(program, rel, sectionIndexToAddress, rel.header.epilogSectionId, rel.header.epilogSectionOffset,
                "epilog", log);
        processCallback(program, rel, sectionIndexToAddress, rel.header.unresolvedSectionId,
                rel.header.unresolvedSectionOffset, "unresolved", log);

        Options programInfo = program.getOptions(Program.PROGRAM_INFO);
        String optionRelBaseAddr = String.format(PROGRAM_INFO_REL_BASE_ADDR, rel.header.moduleId);
        if (!programInfo.isRegistered(optionRelBaseAddr)) {
            programInfo.registerOption(optionRelBaseAddr, "", null, "Base address of a loaded REL file");
        }
        programInfo.setString(optionRelBaseAddr, String.format("%08x", base));
        // TODO: Do we need registerOption()? Seems other loaders doesn't use it?
        if (programInfo.getString(PROGRAM_INFO_MAIN_MODULE_ID, "") == null
                || programInfo.getString(PROGRAM_INFO_MAIN_MODULE_ID, "") == "") {
            programInfo.registerOption(PROGRAM_INFO_MAIN_MODULE_ID, "", null,
                    "Main Module ID of this program for external programs to link to");
            if (isStandalone) {
                programInfo.setString(PROGRAM_INFO_MAIN_MODULE_ID, Long.toUnsignedString(rel.header.moduleId));
            } else {
                programInfo.setString(PROGRAM_INFO_MAIN_MODULE_ID, "0");
            }
        }

        monitor.initialize(0, monitorPrefix + "Done loading REL for now...");
    }

    @Override
    protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project, List<Option> options,
            MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException {
        // TODO Auto-generated method stub
        super.postLoadProgramFixups(loadedPrograms, project, options, messageLog, monitor);
    }

    private void processCallback(Program program, REL rel, Map<Integer, Address> sectionIndexToAddress,
            long sectionIndex, long sectionOffset, String name, MessageLog log) {
        if (sectionIndex != 0) {
            if (sectionIndex >= rel.sections.length) {
                log.appendMsg(String.format("%s section index is invalid", name));
            } else if (sectionOffset >= rel.sections[(int) sectionIndex].size) {
                log.appendMsg(String.format("%s section offset is invalid", name));
            } else {
                Address address = sectionIndexToAddress.get((int) sectionIndex).add(sectionOffset);
                try {
                    program.getSymbolTable().createLabel(address, String.format("_rel%d_%s", rel.header.moduleId, name),
                            SourceType.USER_DEFINED);
                } catch (InvalidInputException e) {
                    log.appendException(e);
                }
                program.getSymbolTable().addExternalEntryPoint(address);
            }
        }
    }

    private void processRelocations(Program program, REL rel, Map<REL.Section, Address> sectionToAddress,
            REL.ImportTableEntry importEntry, REL.RelocationEntry[] relocEntries,
            Map<Integer, Address> otherSectionIndexToAddress, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Memory memory = program.getMemory();
        boolean isBigEndian = program.getLanguage().isBigEndian();
        RelocationTable relocationTable = program.getRelocationTable();
        Address currentAddress = null;

        for (RelocationEntry relocEntry : relocEntries) {
            byte[] originalBytes = null;
            long[] values = { rel.header.moduleId, importEntry.moduleId, relocEntry.symbolSection,
                    relocEntry.symbolOffset };
            long target = -1;

            if (RelocationUtil.doesRelocate(relocEntry.relocationType)) {
                if (otherSectionIndexToAddress != null) {
                    target = otherSectionIndexToAddress.get(relocEntry.symbolSection).add(relocEntry.symbolOffset)
                            .getOffset();
                } else {
                    target = relocEntry.symbolOffset;
                }
            }

            if (currentAddress == null && RelocationUtil.doesRelocate(relocEntry.relocationType)) {
                log.appendMsg("Relocation Source Section has not been set but is being used");
            } else if (currentAddress != null) {
                currentAddress = currentAddress.add(relocEntry.offset);
                originalBytes = new byte[RelocationUtil.getSize(relocEntry.relocationType)];
                if (originalBytes.length != 0) {
                    try {
                        memory.getBytes(currentAddress, originalBytes);
                    } catch (MemoryAccessException e) {
                        log.appendException(e);
                        originalBytes = new byte[0];
                    }
                }
            }

            try {
                if ((!RelocationUtil.isValid(relocEntry.relocationType)
                        && !RelocationUtil.isDolphinExtension(relocEntry.relocationType))
                        || relocEntry.relocationType == RelocationUtil.R_DOLPHIN_MRKREF) {
                    log.appendMsg(String.format("Unknown relocation type: %d", relocEntry.relocationType));
                    if (currentAddress != null && originalBytes != null) {
                        relocationTable.add(currentAddress, Status.UNSUPPORTED, relocEntry.relocationType, values,
                                originalBytes, null);
                    }
                } else if (RelocationUtil.apply(memory, isBigEndian, currentAddress, target,
                        relocEntry.relocationType)) {
                    if (originalBytes.length == 0) {
                        log.appendMsg("This should never happen! We couldn't collect the original bytes.");
                    } else {
                        relocationTable.add(currentAddress, Status.APPLIED, relocEntry.relocationType, values,
                                originalBytes, null);
                    }
                } else if (relocEntry.relocationType == RelocationUtil.R_DOLPHIN_NOP) {
                    // Do nothing
                } else if (relocEntry.relocationType == RelocationUtil.R_DOLPHIN_END) {
                    // Do nothing, this is the last entry
                } else if (relocEntry.relocationType == RelocationUtil.R_DOLPHIN_SECTION) {
                    if (relocEntry.symbolSection < rel.sections.length) {
                        currentAddress = sectionToAddress.get(rel.sections[relocEntry.symbolSection]);
                    } else {
                        log.appendMsg(String.format("Invalid section to relocate to: %d", relocEntry.symbolSection));
                        // OSLink doesn't check this, so it does OOB stuff
                        currentAddress = null;
                    }
                } else if (!RelocationUtil.doesRelocate(relocEntry.relocationType)) {
                    // Do nothing, handles RelocationUtil.R_PPC_NONE
                } else {
                    log.appendMsg(String.format("Unhandled relocation thing: type=%d currentAddress=%s",
                            relocEntry.relocationType, String.valueOf(currentAddress)));
                    if (currentAddress != null && originalBytes != null) {
                        relocationTable.add(currentAddress, Status.UNKNOWN, relocEntry.relocationType, values,
                                originalBytes, null);
                    }
                }
            } catch (MemoryAccessException e) {
                if (currentAddress != null && originalBytes != null
                        && RelocationUtil.doesRelocate(relocEntry.relocationType)) {
                    relocationTable.add(currentAddress, Status.FAILURE, relocEntry.relocationType, values,
                            originalBytes, null);
                }
                log.appendException(e);
            }

            if (monitor != null) {
                monitor.increment();
            }
        }
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> specs = new ArrayList<>();
        BinaryReader reader = new BinaryReader(provider, false);
        try {
            new REL(reader); // Throws exception
            specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:32:Gekko_Broadway", "default"),
                    true));
            return specs;
        } catch (InvalidRELException e) {
            return Collections.emptyList();
        }
    }

    @Override
    public boolean supportsLoadIntoProgram() {
        return true;
    }

    public static final String OPTION_BASE_ADDR = "REL Base Address";
    public static final long OPTION_BASE_ADDR_DEFAULT = 0x85000000L;
    public static final String OPTION_STANDALONE = "REL is Standalone";
    public static final boolean OPTION_STANDALONE_DEFAULT = false;
    public static final String OPTION_IMPORT_HEADER = "REL Import 'Header' Memory";
    public static final boolean OPTION_IMPORT_HEADER_DEFAULT = true;
    public static final String OPTION_IMPORT_SECTION_TABLE = "REL Import 'Section Table' Memory";
    public static final boolean OPTION_IMPORT_SECTION_TABLE_DEFAULT = true;
    public static final String OPTION_IMPORT_IMPORT_TABLE = "REL Import 'Import Table' Memory";
    public static final boolean OPTION_IMPORT_IMPORT_TABLE_DEFAULT = true;
    public static final String OPTION_IMPORT_RELOCATIONS = "REL Import 'Relocations' Memory";
    public static final boolean OPTION_IMPORT_RELOCATIONS_DEFAULT = true;

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean loadIntoProgram) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);

        Address baseAddr = null;
        if (domainObject instanceof Program) {
            Program program = (Program) domainObject;
            AddressFactory addressFactory = program.getAddressFactory();
            if (addressFactory != null) {
                AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
                if (defaultAddressSpace != null) {
                    baseAddr = defaultAddressSpace.getAddress(OPTION_BASE_ADDR_DEFAULT);
                }
            }
        }
        list.add(new Option(OPTION_BASE_ADDR, baseAddr, Address.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
        list.add(new Option(OPTION_IMPORT_HEADER, OPTION_IMPORT_HEADER_DEFAULT, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-importHeader"));
        list.add(new Option(OPTION_IMPORT_SECTION_TABLE, OPTION_IMPORT_SECTION_TABLE_DEFAULT, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-importSectionTable"));
        list.add(new Option(OPTION_IMPORT_IMPORT_TABLE, OPTION_IMPORT_IMPORT_TABLE_DEFAULT, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-importImportTable"));
        list.add(new Option(OPTION_IMPORT_RELOCATIONS, OPTION_IMPORT_RELOCATIONS_DEFAULT, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-importRelocations"));

        if (loadIntoProgram) {
            list.add(new Option(OPTION_STANDALONE, OPTION_STANDALONE_DEFAULT, Boolean.class,
                    Loader.COMMAND_LINE_ARG_PREFIX + "-standalone"));
        }

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        Address baseAddr = null;
        for (Option option : options) {
            String optName = option.getName();
            try {
                if (optName.equals(OPTION_BASE_ADDR)) {
                    baseAddr = (Address) option.getValue();
                }
            } catch (Exception e) {
                if (e instanceof OptionException) {
                    return e.getMessage();
                }
                return String.format("Invalid value for %s: %s", optName, String.valueOf(option.getValue()));
            }
        }

        if (program != null && baseAddr != null) {
            try {
                // TODO: Include BSS size
                if (program.getMemory().intersects(baseAddr, baseAddr.add(provider.length() - 1))) {
                    return "Memory space taken up by something else, change the base address in the options";
                }
            } catch (AddressOutOfBoundsException e) {
                return e.getMessage();
            } catch (IOException e) {
                return e.getMessage();
            }
        }

        return super.validateOptions(provider, loadSpec, options, program);
    }

}
