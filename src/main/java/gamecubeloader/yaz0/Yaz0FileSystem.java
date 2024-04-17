package gamecubeloader.yaz0;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.AbstractFileSystem;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a Single File FileSystem for Yaz0 compressed files, that are commonly
 * found in Nintendo GameCube & Wii games.
 * 
 * @see Yaz0
 * @see Yaz0FileSystemFactory
 */
@FileSystemInfo(type = "yaz0", description = "Yaz0 (GameCube & Wii)", factory = Yaz0FileSystemFactory.class)
public class Yaz0FileSystem extends AbstractFileSystem<Object> {

    /**
     * The Yaz0 file data itself.
     */
    private ByteProvider provider;

    /**
     * The decompressed file data. Filled by
     * {@link #getByteProvider(GFile, TaskMonitor)}.
     */
    private ByteProvider decompressedProvider = null;

    public Yaz0FileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        super(fsFSRL, FileSystemService.getInstance());
        this.provider = provider;
    }

    /**
     * Read and parse the file.
     * 
     * @param monitor The monitor to set status on.
     * @throws IOException If an I/O error occurs during reading.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening Yaz0 archive...");
        Yaz0 header = new Yaz0(provider);

        String fileName = "noname";
        // Try to use the archive name so we have a proper name
        FSRLRoot fsrl = getFSRL();
        if (fsrl != null) {
            FSRL parent = getFSRL().getContainer();
            if (parent != null) {
                if (parent.getName() != null)
                    fileName = parent.getName();
            }
        }

        fsIndex.storeFile(fileName, 1, false, header.uncompressedSize, null);
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
        if (isClosed() || provider == null) {
            return null;
        }
        if (decompressedProvider == null) {
            monitor.setMessage("Decompressing Yaz0 file...");
            decompressedProvider = new ByteProviderWrapper(Yaz0.parseAndDecompress(provider), file.getFSRL());
        }
        return decompressedProvider;
    }

    @Override
    public boolean isStatic() {
        return true;
    }

    @Override
    public boolean isClosed() {
        return provider == null;
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        if (provider != null) {
            provider.close();
            provider = null;
        }
        decompressedProvider = null;
        fsIndex.clear();

    }

}
