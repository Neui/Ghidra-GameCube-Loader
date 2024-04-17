package gamecubeloader.yaz0;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Reads the header of an Yaz0 file. Can also decompress it. This is used by
 * (first-party) Nintendo GameCube & Wii games.
 */
public class Yaz0 implements StructConverter {

    /**
     * The beginning of the file, indicating what type of file this is. This is
     * equivalent to the string {@code "Yaz0"}.
     */
    public static final byte[] magicHeader = { 0x59, 0x61, 0x7A, 0x30 };

    /**
     * Size of the header in bytes.
     */
    public static final int headerSize = 16;

    /**
     * The size (in bytes) of the file uncompressed.
     */
    public long uncompressedSize;

    /**
     * Unknown or unused field, located at offset 8. Appears to be always 0.
     */
    public long unknown8;

    /**
     * Unknown or unused field, located at offset 0xC (12). Appears to be always 0.
     */
    public long unknownC;

    public Yaz0(ByteProvider provider) throws IOException {
        read(provider);
    }

    private void read(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false);
        reader.setPointerIndex(0);
        byte[] fileMagicHeader = reader.readNextByteArray(magicHeader.length);
        if (!Yaz0.hasMagic(fileMagicHeader)) {
            throw new IOException("Magic does not match");
        }

        this.uncompressedSize = reader.readNextUnsignedInt();
        this.unknown8 = reader.readNextUnsignedInt();
        this.unknownC = reader.readNextUnsignedInt();
    }

    /**
     * Determines whenever the specified data starts with the specified file magic,
     * indicating that this is a Yaz0 compressed file.
     * 
     * @param provider The data to examine. It may be {@code null}.
     * @return {@code true} if {@code data} starts with the file magic,
     *         {@code false} if not or {@code data} is {@code null}.
     * @throws IOException If an I/O error occurs.
     */
    public static boolean hasMagic(ByteProvider provider) throws IOException {
        return provider != null && Arrays.equals(magicHeader, provider.readBytes(0, magicHeader.length));
    }

    /**
     * Determines whenever the specified data starts with the specified file magic,
     * indicating that this is a Yaz0 compressed file.
     * 
     * @param data The data to examine. It may be {@code null}.
     * @return {@code true} if {@code data} starts with the file magic,
     *         {@code false} if not or {@code data} is {@code null}.
     */
    public static boolean hasMagic(byte[] data) {
        return data != null && data.length >= magicHeader.length
                && Arrays.equals(magicHeader, 0, magicHeader.length, data, 0, magicHeader.length);
    }

    /**
     * Decompress the file contents. This is not cached, so it may be expensive.
     * 
     * @param provider The compressed file contents with header. Never {@code null}.
     * @return The decompressed file data. Never {@code null}.
     * @throws IOException          When an reading error occurs, or the read
     *                              decompressed size in the header is negative.
     * @throws NullPointerException If {@code provider} is {@code null}.
     */
    public ByteProvider decompress(ByteProvider provider) throws IOException {
        Objects.requireNonNull(provider, "provider must be not be null");
        try {
            return parseAndDecompress(provider);
        } catch (IllegalArgumentException e) {
            throw new IOException(e);
        }
    }

    /**
     * Convenience method to decompress the file (with header).
     * 
     * @param provider The compressed file contents with header. Never {@code null}.
     * @return The decompressed file data. Never {@code null}.
     * @throws IOException          When an reading error occurs, or the read
     *                              decompressed size in the header is negative.
     * @throws NullPointerException If {@code provider} is {@code null}.
     */
    public static ByteProvider parseAndDecompress(ByteProvider provider) throws IOException {
        Objects.requireNonNull(provider, "provider must be not be null");
        var reader = new BinaryReader(provider, false);
        int decompressedSize = reader.readInt(4);
        byte[] decompressBuffer = new byte[decompressedSize];
        return decompressRaw(new ByteProviderWrapper(provider, 0x10, provider.length() - 0x10), decompressedSize);
    }

    /**
     * Decompress the actual file without a header. Use {@link ByteProviderWrapper}
     * to cut off the header, or simply use {@link #parseAndDecompress}.
     * 
     * @param provider         The compressed file contents with header. Never
     *                         {@code null}.
     * @param decompressedSize The decompressed size in bytes. Determines how big
     *                         the returned data is.
     * @return The decompressed file data. Never {@code null}.
     * @throws IOException              When an reading error occurs.
     * @throws NullPointerException     If {@code provider} is {@code null}.
     * @throws IllegalArgumentException If {@code decompressedSize} is negative.
     */
    public static ByteProvider decompressRaw(ByteProvider provider, int decompressedSize) throws IOException {
        Objects.requireNonNull(provider, "provider must be not be null");
        if (decompressedSize < 0) {
            throw new IllegalArgumentException(
                    String.format("Decompressed size is out of bounds (%d)", decompressedSize));
        }

        var reader = new BinaryReader(provider, false);
        byte[] decompressBuffer = new byte[decompressedSize];

        int readPosition = 0;
        int sourceBitfield = 0;
        int writePosition = 0;
        int sourceByte = 0;

        do {
            int localReadPosition = readPosition;

            if (sourceBitfield == 0) {
                sourceByte = reader.readUnsignedByte(readPosition);
                sourceBitfield = 0x80;
                localReadPosition = readPosition + 1;
            }

            if ((sourceByte & sourceBitfield) == 0) {
                readPosition = localReadPosition + 2;

                int bitInfo = reader.readUnsignedShort(localReadPosition);
                int bitAdjustReadOffset = writePosition - (bitInfo & 0x0FFF);
                int writeSize;

                if ((bitInfo >> 12) == 0) {
                    writeSize = reader.readUnsignedByte(readPosition) + 0x12;
                    readPosition = localReadPosition + 3;
                } else {
                    writeSize = ((bitInfo >> 12) & 0xF) + 2;
                }

                while (writeSize != 0) {
                    decompressBuffer[writePosition] = decompressBuffer[bitAdjustReadOffset - 1];
                    writePosition++;
                    bitAdjustReadOffset++;
                    writeSize--;
                }
            } else {
                readPosition = localReadPosition + 1;
                decompressBuffer[writePosition] = (byte) reader.readUnsignedByte(localReadPosition);
                writePosition++;
            }

            sourceBitfield >>= 1;
        } while (writePosition < decompressedSize);

        return new ByteArrayProvider(decompressBuffer);
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure struct = new StructureDataType("Yaz0Header", 0);
        struct.setDescription(
                "Yaz0 is a compressed single file format. The compressed data follows after this header.");
        struct.add(StructConverter.DWORD, "magic", "'Yaz0'");
        struct.add(StructConverter.DWORD, "decompressedSize", "Decompressed size in bytes");
        struct.add(StructConverter.DWORD, "unused8", "Seemingly always 0.");
        struct.add(StructConverter.DWORD, "unusedC", "Seemingly always 0.");
        return struct;
    }

}
