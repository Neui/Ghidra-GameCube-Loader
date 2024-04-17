package gamecubeloader.yaz0;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Yaz0 is a file compression format used by some Nintendo GameCube and Wii
 * games. This is a factory that creates File System objects out of those files
 * to load.
 * 
 * @see Yaz0
 */
public class Yaz0FileSystemFactory
        implements GFileSystemFactoryByteProvider<Yaz0FileSystem>, GFileSystemProbeBytesOnly {

    @Override
    public int getBytesRequired() {
        return Yaz0.magicHeader.length;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
        return Yaz0.hasMagic(startBytes);
    }

    @Override
    public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService,
            TaskMonitor monitor) throws IOException, CancelledException {
        Yaz0FileSystem fileSystem = new Yaz0FileSystem(targetFSRL, byteProvider);
        fileSystem.mount(monitor);
        return fileSystem;
    }

}
