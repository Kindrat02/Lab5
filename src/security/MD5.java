package security;

import java.io.*;

public class MD5 {

    private final MD5State workingState = new MD5State();

    private static final byte[] padding = { (byte) 0x80, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

    private final int [] decodeBuffer = new int[16];

    private final MD5State finalState = new MD5State();

    public MD5() {
        reset();
    }

    public byte [] getHash() {
        if (!finalState.valid) {
            finalState.copy(workingState);
            long bitCount = finalState.bitCount;
            int leftOver = (int) ((bitCount >>> 3) & 0x3f);
            // Compute the amount of padding to add based on number of left over bits.
            int padlen = (leftOver < 56) ? (56 - leftOver) : (120 - leftOver);
            // add the padding
            update(finalState, padding, 0, padlen);
            // add the message length
            update(finalState, encode(bitCount), 0, 8);
            finalState.valid = true;
        }
        // make a copy of the hash before returning it.
        return encode(finalState.state, 16);
    }

    public String getHashString() {
        return toHex(this.getHash());
    }

    public static String getHashString(InputStream in) throws IOException {
        MD5 md5 = new MD5();
        byte [] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            md5.update(buffer, read);
        }
        return md5.getHashString();
    }

    public static String getHashString(File f) throws IOException {
        return getHashString(new FileInputStream(f));
    }

    public static String getHashString(String s) {
        MD5 md5 = new MD5();
        md5.update(s);
        return md5.getHashString();
    }

    public void reset() {
        workingState.reset();
        finalState.valid = false;
    }

    public String toString() {
        return getHashString();
    }

    private void update(MD5State state, byte[] buffer, int offset, int length) {
        finalState.valid = false;

        // if length goes beyond the end of the buffer, cut it short.
        if ((length + offset) > buffer.length) {
            length = buffer.length - offset;
        }

        // that have not been hashed yet
        int index = (int) (state.bitCount >>> 3) & 0x3f;

        state.bitCount += (long) length << 3;
        int partlen = 64 - index;
        int i = 0;
        if (length >= partlen) {
            System.arraycopy(buffer, offset, state.buffer, index, partlen);
            transform(state, decode(state.buffer, 64, 0));
            for (i = partlen; (i + 63) < length; i += 64) {
                transform(state, decode(buffer, 64, i));
            }
            index = 0;
        }

        // buffer remaining input
        if (i < length) {
            for (int start = i; i < length; i++) {
                state.buffer[index + i - start] = buffer[i + offset];
            }
        }
    }

    public void update(byte[] buffer, int offset, int length) {
        update(workingState, buffer, offset, length);
    }

    public void update(byte[] buffer, int length) {
        update(buffer, 0, length);
    }

    public void update(byte[] buffer) {
        update(buffer, 0, buffer.length);
    }

    public void update(String s) {
        update(s.getBytes());
    }

    private class MD5State {

        public boolean valid = true;

        public void reset() {
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;

            bitCount = 0;
        }

        public int[] state = new int[4];

        public long bitCount;

        public byte[] buffer = new byte[64];

        public MD5State() {
            reset();
        }

        public void copy(MD5State from) {
            System.arraycopy(from.buffer, 0, this.buffer, 0,
                    this.buffer.length);
            System.arraycopy(from.state, 0, this.state, 0,
                            this.state.length);
            this.valid = from.valid;
            this.bitCount = from.bitCount;
        }

        public String toString() {
            return state[0] + " " + state[1] + " " + state[2] + " " + state[3];
        }
    }

    private static String toHex(byte[] hash) {
        StringBuilder buf = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            int intVal = b & 0xff;
            if (intVal < 0x10) {
                buf.append("0");
            }
            buf.append(Integer.toHexString(intVal));
        }
        return buf.toString();
    }

    private static int FF(int a, int b, int c, int d, int x, int s, int ac) {
        a += ((b & c) | (~b & d));
        a += x;
        a += ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int GG(int a, int b, int c, int d, int x, int s, int ac) {
        a += ((b & d) | (c & ~d));
        a += x;
        a += ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int HH(int a, int b, int c, int d, int x, int s, int ac) {
        a += (b ^ c ^ d);
        a += x;
        a += ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int II(int a, int b, int c, int d, int x, int s, int ac) {
        a += (c ^ (b | ~d));
        a += x;
        a += ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int rotateLeft(int a, int s) {
        return (a << s) | (a >>> (32 - s));
    }

    private static byte [] encode(long l) {
        byte [] out = new byte[8];
        out[0] = (byte) (l & 0xff);
        out[1] = (byte) ((l >>> 8) & 0xff);
        out[2] = (byte) ((l >>> 16) & 0xff);
        out[3] = (byte) ((l >>> 24) & 0xff);
        out[4] = (byte) ((l >>> 32) & 0xff);
        out[5] = (byte) ((l >>> 40) & 0xff);
        out[6] = (byte) ((l >>> 48) & 0xff);
        out[7] = (byte) ((l >>> 56) & 0xff);
        return out;
    }

    private static byte [] encode(int[] input, int len) {
        byte [] out = new byte[len];
        int i;
        int j;
        for (i = j = 0; j < len; i++, j += 4) {
            out[j] = (byte) (input[i] & 0xff);
            out[j + 1] = (byte) ((input[i] >>> 8) & 0xff);
            out[j + 2] = (byte) ((input[i] >>> 16) & 0xff);
            out[j + 3] = (byte) ((input[i] >>> 24) & 0xff);
        }
        return out;
    }

    private int [] decode(byte[] buffer, int len, int offset) {
        int i, j;
        for (i = j = 0; j < len; i++, j += 4) {
            decodeBuffer[i] = (buffer[j + offset] & 0xff)
                    | ((buffer[j + 1 + offset] & 0xff) << 8)
                    | ((buffer[j + 2 + offset] & 0xff) << 16)
                    | ((buffer[j + 3 + offset] & 0xff) << 24);
        }
        return decodeBuffer;
    }

    private static void transform(MD5State state, int [] x) {
        int a = state.state[0];
        int b = state.state[1];
        int c = state.state[2];
        int d = state.state[3];

        /* Round 1 */
        a = FF(a, b, c, d, x[0], 7, 0xd76aa478); /* 1 */
        d = FF(d, a, b, c, x[1], 12, 0xe8c7b756); /* 2 */
        c = FF(c, d, a, b, x[2], 17, 0x242070db); /* 3 */
        b = FF(b, c, d, a, x[3], 22, 0xc1bdceee); /* 4 */
        a = FF(a, b, c, d, x[4], 7, 0xf57c0faf); /* 5 */
        d = FF(d, a, b, c, x[5], 12, 0x4787c62a); /* 6 */
        c = FF(c, d, a, b, x[6], 17, 0xa8304613); /* 7 */
        b = FF(b, c, d, a, x[7], 22, 0xfd469501); /* 8 */
        a = FF(a, b, c, d, x[8], 7, 0x698098d8); /* 9 */
        d = FF(d, a, b, c, x[9], 12, 0x8b44f7af); /* 10 */
        c = FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
        b = FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
        a = FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
        d = FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
        c = FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
        b = FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

        /* Round 2 */
        a = GG(a, b, c, d, x[1], 5, 0xf61e2562); /* 17 */
        d = GG(d, a, b, c, x[6], 9, 0xc040b340); /* 18 */
        c = GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
        b = GG(b, c, d, a, x[0], 20, 0xe9b6c7aa); /* 20 */
        a = GG(a, b, c, d, x[5], 5, 0xd62f105d); /* 21 */
        d = GG(d, a, b, c, x[10], 9, 0x02441453); /* 22 */
        c = GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
        b = GG(b, c, d, a, x[4], 20, 0xe7d3fbc8); /* 24 */
        a = GG(a, b, c, d, x[9], 5, 0x21e1cde6); /* 25 */
        d = GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
        c = GG(c, d, a, b, x[3], 14, 0xf4d50d87); /* 27 */
        b = GG(b, c, d, a, x[8], 20, 0x455a14ed); /* 28 */
        a = GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
        d = GG(d, a, b, c, x[2], 9, 0xfcefa3f8); /* 30 */
        c = GG(c, d, a, b, x[7], 14, 0x676f02d9); /* 31 */
        b = GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        a = HH(a, b, c, d, x[5], 4, 0xfffa3942); /* 33 */
        d = HH(d, a, b, c, x[8], 11, 0x8771f681); /* 34 */
        c = HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
        b = HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
        a = HH(a, b, c, d, x[1], 4, 0xa4beea44); /* 37 */
        d = HH(d, a, b, c, x[4], 11, 0x4bdecfa9); /* 38 */
        c = HH(c, d, a, b, x[7], 16, 0xf6bb4b60); /* 39 */
        b = HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
        a = HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
        d = HH(d, a, b, c, x[0], 11, 0xeaa127fa); /* 42 */
        c = HH(c, d, a, b, x[3], 16, 0xd4ef3085); /* 43 */
        b = HH(b, c, d, a, x[6], 23, 0x04881d05); /* 44 */
        a = HH(a, b, c, d, x[9], 4, 0xd9d4d039); /* 45 */
        d = HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
        c = HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
        b = HH(b, c, d, a, x[2], 23, 0xc4ac5665); /* 48 */

        /* Round 4 */
        a = II(a, b, c, d, x[0], 6, 0xf4292244); /* 49 */
        d = II(d, a, b, c, x[7], 10, 0x432aff97); /* 50 */
        c = II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
        b = II(b, c, d, a, x[5], 21, 0xfc93a039); /* 52 */
        a = II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
        d = II(d, a, b, c, x[3], 10, 0x8f0ccc92); /* 54 */
        c = II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
        b = II(b, c, d, a, x[1], 21, 0x85845dd1); /* 56 */
        a = II(a, b, c, d, x[8], 6, 0x6fa87e4f); /* 57 */
        d = II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
        c = II(c, d, a, b, x[6], 15, 0xa3014314); /* 59 */
        b = II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
        a = II(a, b, c, d, x[4], 6, 0xf7537e82); /* 61 */
        d = II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
        c = II(c, d, a, b, x[2], 15, 0x2ad7d2bb); /* 63 */
        b = II(b, c, d, a, x[9], 21, 0xeb86d391); /* 64 */

        state.state[0] += a;
        state.state[1] += b;
        state.state[2] += c;
        state.state[3] += d;
    }
}