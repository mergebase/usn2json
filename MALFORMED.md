# Malformed emails

## Malformed subject line

Because of these, when matching the subject line:
- match subject line solely by looking at the starting `Subject: ` part and USN code inside it
- join the following lines, until we see a line that starts with `Something:`

Then parse the USN code:
- without looking for square brackets

Then parse the package name(s):
- strip off everything up to the USN code
- strip off everything up to `Fixed`, `Updated`
- strip off everything starting with `Vuln`, `vuln`, `Regress`, `regress`, `updat`, `bug`, `packag`, `for`, `inform`, `Denial`
- strip off everything starting with `(`
- the package name(s) is/are the remaining string
- an empty package name is acceptable

Note: these have not been accounted for

```txt
2005-September.txt:
Subject: [USN-179-1] openssl weak default configuration

2006-March.txt:
Subject: [USN-262-1] Ubuntu 5.10 installer password disclosure

2010-July.txt:
Subject: [USN-930-5] ant, apturl, Epiphany, gluezilla, gnome-python-extras,
	liferea, mozvoikko, OpenJDK, packagekit, ubufox, webfav, yelp update

2010-June.txt:
Subject: [USN-930-2] apturl, Epiphany, gecko-sharp, gnome-python-extras,
	liferea, rhythmbox, totem, ubufox, yelp update
```

### USN-160-2 (2005-September)

No brackets surrounding USN code

```txt
Subject: USN-160-2: Apache vulnerability
```

### USN-346-2 (2006-September)

Subject line spans multiple lines

```txt
Subject: [USN-346-2] Fixed linux-restricted-modules-2.6.15 for previous Linux
	kernel update
Message-ID: <20060914194632.GE4954@piware.de>
```

### USN-2929-2 (2016 March)

No keyword after the package name

```txt
Subject: [RT.PS #1359219] [USN-2929-2] Linux kernel (Trusty HWE)
```

### USN-1093-1 (2011-March)

This is not an isolated example

```txt
Subject: [USN-1093-1] Linux Kernel vulnerabilities (Marvell Dove)
```

### USN-4518-1 (2020-September)

Missing opening bracket `[`

```txt
Subject: USN-4518-1] xawtv vulnerability
```

### USN-3199-2 (2017-February)

There is an additional bracket before the USN code

```txt
Subject: [RT.PS #2107586] [USN-3199-2] Python Crypto regression
```

### USN-3207-2 (2017-February)

```txt
Subject: [USN-3207-2] Linux kernel (Trusty HWE) vulnerabilities
```

## Malformed special section

Due to these malformed emails, to parse the special section, we now look for the starting marker, and also for the line starting with `Ubuntu Security Notice`.

### USN-1367-4 (2012-February)

The special section has a malformed starting marker:

```txt
1==========================================================================
Ubuntu Security Notice USN-1367-4
February 17, 2012

xulrunner-1.9.2 vulnerability
==========================================================================
```

### USN-4128-1 (2019-September)

The special section is missing the starting marker:

```txt
From emilia.torino at canonical.com  Tue Sep 10 19:30:58 2019
From: emilia.torino at canonical.com (Emilia Torino)
Date: Tue, 10 Sep 2019 16:30:58 -0300
Subject: [USN-4128-1] Tomcat vulnerabilities
Message-ID: <14c2c894-7b97-60bc-f19a-b39e8171970e@canonical.com>

Ubuntu Security Notice USN-4128-1
September 10, 2019

tomcat8 vulnerabilities
==========================================================================
```

