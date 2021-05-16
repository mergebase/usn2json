# Useful One-liners

## Looking for Subject lines with multiple square brackets

From a folder `txt` full of uncompressed email archives:

```sh
$ grep '^Subject:.*\[.*\].*\[.*\].*' txt/*
```

From the output of the command above, see whether the USN codes appear twice:

```sh
$ grep '^Subject:' txt/* | grep -e USN-2929- -e USN-2928- -e USN-3199- -e USN-346-
```

## Look for lines starting with "Ubuntu Security Notice"

This line is found inside the special section after `Message-ID:`.

From a folder `txt` full of uncompressed email archives:

```sh
$ grep '^Ubuntu Security Notice' txt/*.txt | cut -f 2- -d : | sort | uniq | wc
```

From generated json files inside directory `USN`:

```sh
$ grep '"Ubuntu Security Notice' USN/*/*/* | cut -f 2- -d : | sort | uniq | wc
```

## Filter out Updated packages section, for easier browsing

Make an awk script:

```awk
x&&/^  /{next}
x&&(/^$/){next}
x&&(!/^  /)&&(!/^Updated packages/){x=0;print;next}
!/^Updated packages/{print;next}
/^Updated packages/{x=1;next}
```

Use the script to filter an email archive for viewing:

```sh
$ cat 2006-May.txt | awk -f script.awf | less
```

## Find empty lists in the generated JSON

From generated json files inside directory `USN`:

```sh
$ grep '\[\]' USN/*/*/*
```

## Find USN's without safeVersions

From generated json files inside directory `USN`:

```sh
$ grep '\[\]' USN/*/*/* | grep -e safeVersions
```

## Find USN's without cves

From generated json files inside directory `USN`:

```sh
$ grep '\[\]' USN/*/*/* | grep -e cves
```
