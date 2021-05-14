# Sanity Checks

## Number of USN codes

### In the original data

From a folder `txt` full of uncompressed email archives:

```sh
$ grep '^Subject:.*USN-' txt/*.txt | wc -l
```

From the `emails` directory:

```sh
$ gzip -dc emails/*/*/* | grep '^Subject:.*USN-' | wc -l
```

### In the generated data

With generated json files inside directory `USN`:

```sh
$ find USN -type f | wc -l
```

```sh
$ grep '\[USN-' USN/*/*/* | cut -f 1 -d : | sort | wc -l
```

## Look for missing USN codes

### In the original data

From a folder `txt` full of uncompressed email archives:

```sh
$ grep -E '^Subject:.*USN-[[:digit:]]+-[[:digit:]]+' txt/*.txt | sed -E 's,.*(USN-[[:digit:]]+-[[:digit:]]+).*USN.*,\1,' | sed -E 's,.*(USN-[[:digit:]]+-[[:digit:]]+).*,\1,' | sort | uniq > list-grep-usn.txt
```

From the `emails` directory:

```sh
$ gzip -dc emails/*/*/* | grep -E '^Subject:.*USN-[[:digit:]]+-[[:digit:]]+' | sed -E 's,.*(USN-[[:digit:]]+-[[:digit:]]+).*,\1,' | sort | uniq > list-grep-usn.txt
```

### In the generated data

With generated json files inside directory `USN`:

```sh
$ find USN -type f | sed -E 's,.*(USN-[[:digit:]]+-[[:digit:]]+).*,\1,' | sort | uniq > list-json-usn.txt
```

Checking inside the saved raw email data in the generated JSON files:

```sh
$ grep -E '"Subject:.*USN-[[:digit:]]+-[[:digit:]]+' USN/*/*/* | sed -E 's,.*(USN-[[:digit:]]+-[[:digit:]]+).*,\1,' | sort | uniq > list-json-grep-usn.txt
```

## Look for non-standard subject lines

From a folder `txt` full of uncompressed email archives:

```sh
$ grep '^Subject:' txt/*.txt | grep USN | grep -v -E -e '(V|v)ulnerab\w+$' -e '(R|r)egress\w+$' -e 'updat\w+$'
```

From the `emails` directory:

```sh
$ gzip -dc emails/*/*/* | grep '^Subject:' | grep USN- | grep -v -E -e '(V|v)ulnerab\w+$' -e '(R|r)egress\w+$' -e 'updat\w+$'
```
