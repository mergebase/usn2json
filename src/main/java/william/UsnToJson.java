package william;

import com.mergebase.util.Java2Json;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.GZIPInputStream;
import java.nio.file.*;

public class UsnToJson {
    private static void printUsage() {
        System.out.println("Usage: java -jar UsnToJson.jar <DIRECTORY|FILE> [stdout]");
    }

    public static void main(String[] args) {
        if (args.length != 1 && args.length != 2) {
            printUsage();
            return;
        }

        boolean writeToStdout = false;
        if (args.length == 2) {
            if (args[1].equals("stdout")) {
                writeToStdout = true;
            }
        }

        Path path = Paths.get(args[0]);
        if (Files.isDirectory(path)) {
            String[] fileList = new File(args[0]).list();
            for (String filename : fileList) {
                Path directoryEntry = Paths.get(args[0], filename);
                if (Files.isRegularFile(directoryEntry) || Files.isSymbolicLink(directoryEntry)) {
                    processFile(directoryEntry.toString(), writeToStdout);
                }
            }
        } else if (Files.isRegularFile(path)) {
            processFile(args[0], writeToStdout);
        }
    }

    private static LinkedHashMap<String, Object> reorder(LinkedHashMap<String, Object> usn) {
        LinkedHashMap<String, Object> orderedUsn = new LinkedHashMap<>();

        orderedUsn.put("message-id", usn.getOrDefault("message-id", ""));
        orderedUsn.put("id", usn.getOrDefault("id", ""));
        orderedUsn.put("date", usn.getOrDefault("date", ""));
        orderedUsn.put("project", usn.getOrDefault("project", ""));
        orderedUsn.put("description", usn.getOrDefault("description", ""));
        orderedUsn.put("cves", usn.getOrDefault("cves", new ArrayList<>()));
        orderedUsn.put("safeVersions", usn.getOrDefault("safeVersions", new HashMap<String, String>()));

        return orderedUsn;
    }

    private static void printToFile(LinkedHashMap<String, Object> usn, String year, String month) {
        Object id = usn.get("id");
        if (id == null || !(id instanceof String) || ((String) id).length() < 1) {
            return;
        }

        String usnCode = (String) id;
        String dirname = Paths.get("USN", year, month).toString();
        String filename = Paths.get(dirname, usnCode + ".json").toString();
        System.out.printf("Writing to %s ...\n", filename);

        PrintWriter printWriter = null;
        try {
            new File(dirname).mkdirs();
            printWriter = new PrintWriter(new FileWriter(filename));
            printWriter.print(Java2Json.format(true, reorder(usn)));
        } catch (IOException e) {
            System.out.println(e.toString());
        } finally {
            if (printWriter != null) {
                printWriter.close();
            }
        }
    }

    private static void printToStdout(LinkedHashMap<String, Object> usn) {
        // no point printing if we didn't get the USN code
        Object id = usn.get("id");
        if (id == null || !(id instanceof String) || ((String) id).length() < 1) {
            return;
        }

        System.out.printf("Dumping %s to stdout...\n", (String) id);
        System.out.print(Java2Json.format(true, reorder(usn)));
        System.out.println();
    }

    public static void processFile(String filename, boolean writeToStdout) {
        if (filename == null) {
            return; // sanity check
        }

        String compressionMethod;
        Pattern usnFilename = Pattern.compile("^([0-9]{4})-([A-Z][a-z]+)(\\.\\S+)$");
        Matcher matcher = usnFilename.matcher(Paths.get(filename).getFileName().toString()); // REFACTOR

        // System.out.println("File: " + filename);
        if (!matcher.matches()) {
            return;
        }

        if (matcher.group(3).equals(".txt")) {
            compressionMethod = "";
        } else if (matcher.group(3).equals(".txt.gz")) {
            compressionMethod = "gzip";
        } else {
            return; // skip file
        }

        processFile(filename, compressionMethod, matcher.group(1), matcher.group(2), "UTF-8", writeToStdout);
    }

    public static void processFile(String filename, String compression, String year, String month, String encoding,
            boolean writeToStdout) {
        if (filename == null || filename.length() < 1) {
            return;
        }
        if (year == null || year.length() < 1) {
            return;
        }
        if (month == null || month.length() < 1) {
            return;
        }

        if (compression == null) {
            compression = "";
        }
        if (encoding == null) {
            encoding = "UTF-8";
        }

        System.out.printf("Analyzing %s...\n", filename);

        BufferedReader bufferedReader = null;
        try {
            // support .txt and .txt.gz
            if (compression.equals("gzip")) {
                bufferedReader = new BufferedReader(
                        new InputStreamReader(new GZIPInputStream(new FileInputStream(filename)), encoding));
            } else if (compression.equals("")) {
                bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filename), encoding));
            } else {
                return; // unknown compression method
            }

            Pattern initialFromLine = Pattern.compile(
                    "^From\\s+\\S+\\s+at\\s+\\S+\\s+\\w{3}\\s+\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4}\\s*$");

            Pattern messageIdLine = Pattern.compile("^Message-ID:\\s+(<[\\w\\.@]+>)\\s*$");

            // match the USN code inside brackets, and
            // match project name which is everything before the last word (may be
            // vulnerability, regression, ...)
            Pattern subjectLine = Pattern.compile("^Subject:\\s+\\[(USN-[^\\]]+)\\]\\s+(.+)\\s+\\w+\\s*$");

            Pattern dateLine = Pattern.compile("^Date:\\s+(\\S.*\\S)\\s*$");

            Pattern summaryLine = Pattern.compile("^Summary:\\s*$");

            Pattern referencesLine = Pattern.compile("^References:\\s*$");
            Pattern cveLine = Pattern.compile("^  CVE-\\d{4}-\\d{4,7}.*$");
            // this ASCII bar is used for the special section after Message-ID:
            // before 2011-May, this section contains the CVE lines
            // some of these have trailing spaces, some may be longer than 59 chars
            Pattern equals59xLine = Pattern.compile("^===========================================================*\\s*$");

            Pattern updateInstructionsLine = Pattern.compile("^Update instructions:\\s*$");
            Pattern theProblemLine = Pattern
                    .compile("^The problem can be corrected by (installing|updating|upgrading) .*");
            // I have seen only LTS and ESM tags after the version number
            Pattern ubuntuVersionLine = Pattern.compile("^Ubuntu\\s+(\\S.*\\S)(\\s+(LTS|ESM))?:\\s*$");
            Pattern safePackageVersionLine = Pattern.compile("^  (\\S+)\\s+(\\S+)\\s*$");

            String inputLine;

            boolean firstUsnFound = false;
            LinkedHashMap<String, Object> usn = new LinkedHashMap<>();

            inputLine = bufferedReader.readLine();
            boolean readNextInputLine = false;
            while (true) {
                // always read next line, unless it's been read already
                if (readNextInputLine) {
                    inputLine = bufferedReader.readLine();
                } else {
                    readNextInputLine = true;
                }

                // System.out.println("DEBUG " + inputLine);
                // end of stream, print if we have some valid data
                if (inputLine == null) {
                    if (firstUsnFound) {
                        if (writeToStdout) {
                            printToStdout(usn);
                        } else {
                            printToFile(usn, year, month);
                        }
                    }
                    break;
                }

                // found new from: line, print if we have some valid data
                // there might be leading garbage before the first from: line, don't print it
                Matcher matcher = initialFromLine.matcher(inputLine);
                if (matcher.matches()) {
                    if (firstUsnFound) {
                        if (writeToStdout) {
                            printToStdout(usn);
                        } else {
                            printToFile(usn, year, month);
                        }
                    } else {
                        firstUsnFound = true;
                        usn = new LinkedHashMap<>();
                    }
                    continue;
                }

                // Message-ID: <20210104135457.GA3338405@d4rkl41n>
                matcher = messageIdLine.matcher(inputLine);
                if (matcher.matches()) {
                    usn.put("message-id", matcher.group(1));
                    continue;
                }

                // Subject: [USN-4673-1] libproxy vulnerability
                matcher = subjectLine.matcher(inputLine);
                if (matcher.matches()) {
                    usn.put("id", matcher.group(1));
                    usn.put("project", matcher.group(2));
                    continue;
                }

                // Date: Mon, 4 Jan 2021 10:54:57 -0300
                matcher = dateLine.matcher(inputLine);
                if (matcher.matches()) {
                    usn.put("date", matcher.group(1));
                    continue;
                }

                // Summary:
                //
                // libproxy could be made to crash or execute arbitrary code if it received a
                // specially crafted file.
                //
                // Software Description:
                matcher = summaryLine.matcher(inputLine);
                if (matcher.matches()) {
                    // skip over the empty lines after the section label
                    // stop when we find the next non-empty line
                    do {
                        inputLine = bufferedReader.readLine().trim();
                    } while (inputLine != null && inputLine.length() < 1);

                    // summary is the first non-empty lines after the section label
                    // stop when we find the next empty line
                    String tmpDescription = inputLine;
                    while ((inputLine = bufferedReader.readLine()) != null && inputLine.length() > 0) {
                        tmpDescription += " " + inputLine.trim();
                    }

                    usn.put("description", tmpDescription);

                    // the next line has already been read
                    readNextInputLine = false;
                    continue;
                }

                // References:
                // ..https://usn.ubuntu.com/4686-1
                // ..CVE-2018-5727, CVE-2020-27814, CVE-2020-27824, CVE-2020-27841,
                // ..CVE-2020-27842, CVE-2020-27843, CVE-2020-27845, CVE-2020-6851,
                // ..CVE-2020-8112
                // -------------- next part --------------
                // A non-text attachment was scrubbed...
                matcher = referencesLine.matcher(inputLine);
                if (matcher.matches()) {
                    // read all lines beginning with two spaces
                    // stop when the line does not begin with two spaces
                    String tempCveStr = "";
                    while ((inputLine = bufferedReader.readLine()) != null && inputLine.startsWith("  ")) {
                        // some lines beginning with two spaces are not CVEs
                        // we only want the CVEs
                        if (cveLine.matcher(inputLine).matches()) {
                            tempCveStr += " " + inputLine.trim();
                        }
                    }

                    // Note: in 2011-April, some CVE's are not separated by a comma
                    ArrayList<String> tmpCveList = new ArrayList<String>(
                            Arrays.asList(tempCveStr.trim().split("\\s*(,|\\s)\\s*")));
                    usn.put("cves", tmpCveList);

                    // the next line has already been read
                    readNextInputLine = false;
                    continue;
                }

                // ===========================================================
                // Ubuntu Security Notice USN-38-1.................December 14, 2004
                // linux-source-2.6.8.1 vulnerabilities
                // CAN-2004-0814, CAN-2004-1016, CAN-2004-1056, CAN-2004-1058,
                // CAN-2004-1068, CAN-2004-1069, CAN-2004-1137, CAN-2004-1151
                // ===========================================================

                // ===========================================================
                // Ubuntu Security Notice USN-231-1........December 22, 2005
                // linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities
                // CVE-2005-3257, CVE-2005-3783, CVE-2005-3784, CVE-2005-3805,
                // CVE-2005-3806, CVE-2005-3808, CVE-2005-3848, CVE-2005-3857,
                // CVE-2005-3858
                // ===========================================================

                // System.out.println("CHECK " + inputLine);
                matcher = equals59xLine.matcher(inputLine);
                if (matcher.matches()) {
                    // look for the section end marker
                    // System.out.println("MASUK " + inputLine);
                    String tempCveStr = "";
                    while ((inputLine = bufferedReader.readLine()) != null
                            && !inputLine.startsWith("===========================================================")) {
                        // the keywords may not appear at the start of the line
                        // System.out.println("DEBUG " + inputLine);
                        if (inputLine.contains("CVE-") || inputLine.contains("CAN-")) {
                            tempCveStr += " " + inputLine.trim();
                        }
                    }

                    // Note: in 2011-April, some CVE's are not separated by a comma
                    ArrayList<String> tmpCveList = new ArrayList<String>(
                            Arrays.asList(tempCveStr.trim().split("\\s*(,|\\s)\\s*")));

                    // filter this list, because some entries are not CAN / CVE
                    // ignore MFSA and USN in this section
                    tmpCveList.removeIf(s -> (!s.startsWith("CAN-") && !s.startsWith("CVE-")));

                    usn.put("cves", tmpCveList);

                    // if the last line read in was the closing marker, read another line
                    if (inputLine != null
                            && inputLine.startsWith("===========================================================")) {
                        readNextInputLine = true;
                    } else {
                        // the next line has already been read
                        readNextInputLine = false;
                    }

                    continue;
                }

                // Note: for USN's older than 2011-May, the Update instructions: line
                // may be missing

                // Update instructions:
                //
                // The problem can be corrected by updating your system to the following
                // package versions:
                //
                // Ubuntu 20.10:
                // ..libproxy1v5.....................0.4.15-13ubuntu1.1
                //
                // Ubuntu 20.04 LTS:
                // ..libproxy1v5.....................0.4.15-10ubuntu1.2
                //
                // Ubuntu 18.04 LTS:
                // ..libproxy1v5.....................0.4.15-1ubuntu0.2
                //
                // Ubuntu 16.04 LTS:
                // ..libproxy1v5.....................0.4.11-5ubuntu1.2
                //
                // In general, a standard system update will make all the necessary changes.
                //
                // References:
                // ..https://usn.ubuntu.com/4673-1
                // ..CVE-2020-26154
                matcher = updateInstructionsLine.matcher(inputLine);
                if (!matcher.matches()) {
                    matcher = theProblemLine.matcher(inputLine);
                }
                if (matcher.matches()) {
                    // skip lines after the section header, until we find a Ubuntu version line
                    // or we find an empty line
                    while ((inputLine = bufferedReader.readLine()) != null) {
                        if (ubuntuVersionLine.matcher(inputLine).matches()) {
                            break;
                        }
                        if (inputLine.trim().length() < 1) {
                            break;
                        }
                    }

                    ArrayList<LinkedHashMap<String, String>> tmpSafeVersionList = new ArrayList<>();
                    String ubuntuVersion = "";
                    while (inputLine != null) {
                        Matcher m;
                        // - we can get a new ubuntu version line multiple times
                        // - when we find a safe package version line, associate it with the preceding
                        // ..ubuntu version
                        // - ignore empty lines
                        // - as soon as we find a non-empty line that does not match a ubuntu version
                        // ..line or a safe package version line, we know that the section has ended
                        if ((m = ubuntuVersionLine.matcher(inputLine)) != null && m.matches()) {
                            ubuntuVersion = m.group(1);
                        } else if ((m = safePackageVersionLine.matcher(inputLine)) != null && m.matches()) {
                            LinkedHashMap<String, String> tmpSafeVersion = new LinkedHashMap<>();
                            tmpSafeVersion.put("ubuntu", ubuntuVersion);
                            tmpSafeVersion.put("pkg", m.group(1));
                            tmpSafeVersion.put("v", m.group(2));
                            tmpSafeVersionList.add(tmpSafeVersion);
                        } else if (inputLine.trim().length() < 1) {
                            // ignore
                        } else {
                            break;
                        }

                        inputLine = bufferedReader.readLine();
                        continue;
                    }
                    usn.put("safeVersions", tmpSafeVersionList);

                    // the next line has already been read
                    readNextInputLine = false;
                    continue;
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + filename);
        } catch (UnsupportedEncodingException e) {
            System.out.println("Unsupported encoding: " + "UTF-8");
        } catch (IOException e) {
            System.out.println("Error reading file: " + filename);
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return;
    }

}
