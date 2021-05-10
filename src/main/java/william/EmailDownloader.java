package william;

import com.mergebase.util.Bytes;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Calendar;
import java.util.TimeZone;

public class EmailDownloader {

    public static void main(String[] args) {

        TimeZone gmt = TimeZone.getTimeZone("GMT");
        TimeZone hawaii = TimeZone.getTimeZone("Pacific/Honolulu");
        if (gmt.equals(hawaii)) {
            // Java returns GMT if it doesn't recognize the "getTimeZone()" we requested.
            throw new RuntimeException("HAWAII time zone should not = GMT !");
        }

        Calendar cal = Calendar.getInstance(hawaii);
        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH) + 1;  // stupid java indexes months from 0=January
        int yearMonth = year * 100 + month;

        int count = 1;
        while (yearMonth >= 200410) {
            System.out.println(count + ".) - " + year + " - " + month);
            count++;

            String monthString = monthToWord(month);
            String targetPath = "emails/" + year + "/" + pad(month) + "-" + monthString + "/" + year + "-" + monthString + ".txt.gz";
            File targetFile = new File(targetPath);
            targetFile.getParentFile().mkdirs();

            boolean alreadyDownloaded = targetFile.canRead();
            if (!alreadyDownloaded) {
                download(targetFile);
            }

            if (yearMonth % 100 == 1) {
                year--;
                month = 12;
            } else {
                month--;
            }
            yearMonth = year * 100 + month;
        }

    }

    private static void download(File target) {
        String urlRoot = "https://lists.ubuntu.com/archives/ubuntu-security-announce/";
        String url = urlRoot + target.getName();

        if (target.canRead() && target.length() > 1) {
            // Skip - already downloaded!
            return;
        }

        try {
            URL u = new URL(url);
            URLConnection conn = u.openConnection();
            conn.connect();
            InputStream in = conn.getInputStream();
            Bytes.streamToFile(in, target, true);
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to download [" + url + "]");
        }

        try {
            Thread.sleep(515L);
        } catch (InterruptedException ie) {
            System.out.println("Interrupted??? " + ie);
        }

    }

    private static String monthToWord(int i) {
        switch (i) {
            case 1:
                return "January";
            case 2:
                return "February";
            case 3:
                return "March";
            case 4:
                return "April";
            case 5:
                return "May";
            case 6:
                return "June";
            case 7:
                return "July";
            case 8:
                return "August";
            case 9:
                return "September";
            case 10:
                return "October";
            case 11:
                return "November";
            case 12:
                return "December";
            default:
                throw new IllegalArgumentException("not a month: [" + i + "]");
        }
    }

    private static String pad(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("no negative numbers here please!");
        }
        if (i < 10) {
            return "0" + i;
        } else {
            return "" + i;
        }
    }

}
