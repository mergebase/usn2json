package com.mergebase.util;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.jar.JarFile;
import java.util.zip.ZipFile;

public class Util {

    private static final int REGULAR_CLOSE = 0;
    private static final int CLOSE_AND_COMMIT = 1;

    public static void close(Object o1) {
        close(o1, null, null, null, null);
    }

    public static void close(Object o1, Object o2) {
        close(o1, o2, null, null, null);
    }

    public static void close(Object o1, Object o2, Object o3) {
        close(o1, o2, o3, null, null);
    }

    public static void close(Object o1, Object o2, Object o3, Object o4, Object o5) {
        close(REGULAR_CLOSE, o1, o2, o3, o4, o5);
    }

    private static void close(int flag, Object... closeArgs) {
        if (closeArgs == null || closeArgs.length == 0) {
            return;
        }

        LinkedList<Throwable> closingProblems = new LinkedList<>();
        for (Object o : closeArgs) {
            if (o == null) {
                continue;
            }
            try {
                if (o instanceof ResultSet) ((ResultSet) o).close();
                else if (o instanceof Statement) ((Statement) o).close();
                else if (o instanceof Connection) ((Connection) o).close();
                else if (o instanceof Reader) ((Reader) o).close();
                else if (o instanceof Writer) ((Writer) o).close();
                else if (o instanceof InputStream) ((InputStream) o).close();
                else if (o instanceof OutputStream) ((OutputStream) o).close();
                else if (o instanceof JarFile) ((JarFile) o).close();
                else if (o instanceof ZipFile) ((ZipFile) o).close();
                else if (o instanceof Process) ((Process) o).destroy();
                else if (o instanceof Closeable) ((Closeable) o).close();
                else {
                    throw new IllegalArgumentException("cannot close: " + o.getClass());
                }
            } catch (Throwable t) {
                closingProblems.add(t);
            }
        }

        // Let the close & commit method above handle this instead.
        if (flag == CLOSE_AND_COMMIT && !closingProblems.isEmpty()) {
            throw new CloseFailedException(closingProblems);
        }

        if (!closingProblems.isEmpty()) {
            Throwable t = closingProblems.get(0);
            rethrowIfUnchecked(t);
            throw new RuntimeException("Failed to close something: " + t, t);
        }
    }

    private static class CloseFailedException extends RuntimeException {
        public final LinkedList<Throwable> closingProblems;

        public CloseFailedException(LinkedList<Throwable> closingProblems) {
            this.closingProblems = closingProblems;
        }
    }

    public static void rethrowIfUnchecked(Throwable t) {
        if (t instanceof Error) {
            throw (Error) t;
        } else if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
        }
    }

    public static void rethrowIfSQLExceptionOrUnchecked(Throwable t) throws SQLException {
        if (t instanceof SQLException) {
            throw (SQLException) t;
        }
        rethrowIfUnchecked(t);
    }

    public static String toSqlSafeString(Throwable t) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream(1024);
            PrintStream ps = new PrintStream(byteOut, false, "UTF-8");
            t.printStackTrace(ps);
            ps.flush();
            ps.close();


            String stack = byteOut.toString("UTF-8");
            StringBuilder buf = new StringBuilder(stack.length() * 2);

            // Stuff in a very grep-friendly sentinel.
            buf.append("-- MERGEBASE-SQL-SAFE-ERROR ").append('\n');

            StringReader sr = new StringReader(stack);
            BufferedReader br = new BufferedReader(sr);
            String line;
            try {
                while ((line = br.readLine()) != null) {
                    // SQL parsers ignore lines that start with "-- ".
                    buf.append("-- ").append(line).append('\n');
                }
            } catch (IOException ioe) {
                throw new RuntimeException("impossible - backed by StringReader");
            }
            return buf.toString();

        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("UTF-8 is always supported so this is impossible - " + uee, uee);
        }
    }


}
