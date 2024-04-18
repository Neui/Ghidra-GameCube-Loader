package gamecubeloader.yaz0;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public class Yaz0Test {

    @Test
    public void testHasMagicByteArray() {
        assertTrue(Yaz0.hasMagic(Yaz0.magicHeader));
        assertTrue(Yaz0.hasMagic(new byte[] { 0x59, 0x61, 0x7A, 0x30, 0x00, 0x00, 0x00, 0x00 }));
        assertFalse(Yaz0.hasMagic(new byte[] { 0x59, 0x61, 0x6A, 0x30, 0x00, 0x00, 0x00, 0x00 }));
        assertFalse(Yaz0.hasMagic(new byte[] { 0x59, 0x62, 0x7A, 0x30 }));
        assertFalse(Yaz0.hasMagic(new byte[] { 0x59, 0x61, 0x7A }));
        assertFalse(Yaz0.hasMagic(new byte[] { 0x59, 0x61 }));
        assertFalse(Yaz0.hasMagic(new byte[] { 0x59 }));
        assertFalse(Yaz0.hasMagic(new byte[] {}));
        assertFalse(Yaz0.hasMagic((byte[]) null));
    }

    @Test
    public void testHasMagicByteProvider() throws IOException {
        assertTrue(Yaz0.hasMagic(new ByteArrayProvider(Yaz0.magicHeader)));
        assertTrue(Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59, 0x61, 0x7A, 0x30, 0x00, 0x00, 0x00, 0x00 })));
        assertFalse(
                Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59, 0x61, 0x6A, 0x30, 0x00, 0x00, 0x00, 0x00 })));
        assertFalse(Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59, 0x62, 0x7A, 0x30 })));
        assertThrows(IOException.class, () -> Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59, 0x61, 0x7A })));
        assertThrows(IOException.class, () -> Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59, 0x61 })));
        assertThrows(IOException.class, () -> Yaz0.hasMagic(new ByteArrayProvider(new byte[] { 0x59 })));
        assertThrows(IOException.class, () -> Yaz0.hasMagic(new ByteArrayProvider(new byte[] {})));
        assertFalse(Yaz0.hasMagic((ByteProvider) null));
    }

}
