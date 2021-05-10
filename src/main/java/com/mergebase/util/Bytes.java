package com.mergebase.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class Bytes {

    public static final int SIZE_KEY = 0;
    public static final int LAST_READ_KEY = 1;

    public static byte[] fileToAtMost32KB(File f) {
        FileInputStream fin;
        try {
            fin = new FileInputStream(f);
            if (f.length() <= 32768) {
                try {
                    byte[] buf = new byte[(int) f.length()];
                    fill(buf, 0, fin);
                    return buf;
                } finally {
                    fin.close();
                }
            } else {
                return streamToBytes(fin, true, false);
            }
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to read file [" + f.getName() + "] " + ioe, ioe);
        }
    }

    public static byte[] fileToBytes(File f) {
        FileInputStream fin;
        try {
            fin = new FileInputStream(f);
            if (f.length() <= 32768) {
                try {
                    byte[] buf = new byte[(int) f.length()];
                    fill(buf, 0, fin);
                    return buf;
                } finally {
                    fin.close();
                }
            } else {
                return streamToBytes(fin);
            }
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to read file [" + f.getName() + "] " + ioe, ioe);
        }
    }

    public static String fileToString(File f) {
        byte[] bytes = fileToBytes(f);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static byte[] streamToBytes(final InputStream in) throws IOException {
        return streamToBytes(in, true);
    }

    public static String streamToString(final InputStream in) throws IOException {
        byte[] bytes = streamToBytes(in, true);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static byte[] streamToBytes(final InputStream in, final boolean doClose) throws IOException {
        return streamToBytes(in, doClose, true);
    }

    public static byte[] streamToBytes(
            final InputStream in, final boolean doClose, final boolean doResize
    ) throws IOException {
        byte[] buf = new byte[32768];
        try {
            int[] status = fill(buf, 0, in);
            int size = status[SIZE_KEY];
            int lastRead = status[LAST_READ_KEY];
            if (doResize) {
                while (lastRead != -1) {
                    buf = resizeArray(buf);
                    status = fill(buf, size, in);
                    size = status[SIZE_KEY];
                    lastRead = status[LAST_READ_KEY];
                }
            }
            if (buf.length != size) {
                byte[] smallerBuf = new byte[size];
                System.arraycopy(buf, 0, smallerBuf, 0, size);
                buf = smallerBuf;
            }
        } finally {
            if (doClose) {
                in.close();
            }
        }
        return buf;
    }

    public static long streamToFile(
            InputStream in, File file, boolean doClose
    ) throws IOException {
        return streamToFile(in, file, doClose, false);
    }

    public static long streamToFile(
            InputStream in, File file, boolean doClose, boolean doAppend
    ) throws IOException {
        FileOutputStream fout = null;
        try {
            fout = new FileOutputStream(file, doAppend);
            return streamToOut(in, fout, doClose);
        } finally {
            if (fout != null) {
                fout.close();
            }
        }
    }

    public static long streamToOut(
            InputStream in, OutputStream out, boolean doClose
    ) throws IOException {
        byte[] buf = new byte[32768];
        long writeCount = 0;
        try {
            int read = -1;
            do {
                read = in.read(buf);
                if (read > 0) {
                    writeCount += read;
                    out.write(buf, 0, read);
                }
            } while (read >= 0);

        } finally {
            IOException ioe = null;
            try {
                out.flush();
                if (doClose) {
                    in.close();
                    in = null;
                }
                out.close();
                out = null;
            } catch (IOException e) {
                ioe = e;
            }

            if (doClose) {
                Util.close(in, out);
            } else {
                Util.close(out);
            }
            if (ioe != null) {
                throw ioe;
            }
        }
        return writeCount;
    }

    public static int[] fill(
            final byte[] buf, final int offset, final InputStream in
    ) throws IOException {
        int read = in.read(buf, offset, buf.length - offset);
        int lastRead = read;
        if (read == -1) {
            read = 0;
        }
        while (lastRead != -1 && read + offset < buf.length) {
            lastRead = in.read(buf, offset + read, buf.length - read - offset);
            if (lastRead != -1) {
                read += lastRead;
            }
        }
        return new int[]{offset + read, lastRead};
    }

    public static byte[] resizeArray(final byte[] bytes) {
        byte[] biggerBytes = new byte[bytes.length * 2];
        System.arraycopy(bytes, 0, biggerBytes, 0, bytes.length);
        return biggerBytes;
    }

    /**
     * Knuth-Morris-Pratt
     *
     * @param data    search data
     * @param pattern pattern to look for
     * @return index of match or -1 if no match
     */
    public static int kmp(byte[] data, byte[] pattern) {
        if (data.length == 0) return -1;

        int[] failure = kmpFailure(pattern);
        int j = 0;

        for (int i = 0; i < data.length; i++) {
            while (j > 0 && pattern[j] != data[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == data[i]) {
                j++;
            }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }

    private static int[] kmpFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j > 0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }

}
