# Malformed emails

Table of Contents
* [Malformed subject line](#malformed-subject-line)
* [Malformed special section](#malformed-special-section)
* [Malformed References section](#malformed-references-section)
* [Malformed safe versions section](#malformed-safe-versions-section)
* [Miscellaneous](#miscellaneous)

Note: this is not an exhaustive list

## Malformed subject line

Because of these, when matching the subject line:
- match subject line solely by looking at the starting `Subject: ` part and USN code inside it
- join the following lines, until
	- we see a line that doesn't start with a tab, or
	- we see a line that starts with `Something:`

Ignore the email if:
- there is more than one pair square brackets, see for example `USN-3199-2`
- there is no USN code in the subject line (this kind of subject line won't be matched anyway in the first place)

Then parse the USN code:
- without looking for square brackets

Then parse the package name(s):
- strip off everything up to the USN code
- strip off everything up to `Fixed`, `Updated`
- strip off everything starting with `Vulnerab`, `vulnerab`, `Regress`, `regress`, `updat`, `bug`, `packag`, `for`, `inform`, `Denial`
- strip off everything starting with `(`
- the package name(s) is/are the remaining string
- an empty package name is acceptable

Note: these have not been accounted for, so the words after the closing square bracket will become the "project name"

```txt
2005-September.txt:
Subject: [USN-179-1] openssl weak default configuration

2006-March.txt:
Subject: [USN-262-1] Ubuntu 5.10 installer password disclosure
```

### USN-160-2 (2005-September)

No brackets surrounding USN code, and there is an extra `:` after the USN code

```txt
Subject: USN-160-2: Apache vulnerability
```

### USN-186-2 (2005-September)

USN code appears twice.

```txt
Subject: [USN-186-2] Ubuntu 4.10 packages for USN-186-1 Firefox security
	update
```

### USN-346-2 (2006-September)

Subject line spans multiple lines

```txt
Subject: [USN-346-2] Fixed linux-restricted-modules-2.6.15 for previous Linux
	kernel update
Message-ID: <20060914194632.GE4954@piware.de>
```

### USN-930-2 (2010-June)

Subject line spanning multiple lines and multiple projects in the subject line

```txt
Subject: [USN-930-2] apturl, Epiphany, gecko-sharp, gnome-python-extras,
	liferea, rhythmbox, totem, ubufox, yelp update
```

### USN-1093-1 (2011-March)

This is not an isolated example

```txt
Subject: [USN-1093-1] Linux Kernel vulnerabilities (Marvell Dove)
```

### USN-3199-2 (2017-February)

There is an additional bracket before the USN code, **THESE EMAILS HAVE TO BE SKIPPED**

```txt
Subject: [RT.PS #2107586] [USN-3199-2] Python Crypto regression
```

### USN-3207-2 (2017-February)

```txt
Subject: [USN-3207-2] Linux kernel (Trusty HWE) vulnerabilities
```

### USN-3326-1 (2017-June)

No keyword after the package name

```txt
Subject: [USN-3326-1] Linux kernel
```

### USN-4518-1 (2020-September)

Missing opening bracket `[`

```txt
Subject: USN-4518-1] xawtv vulnerability
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

## Malformed References section

### USN-1211-1 (2011-September)

Trailing garbage after `References:`

```txt
References:sup
  http://www.ubuntu.com/usn/usn-1211-1
  CVE-2011-1020, CVE-2011-1493, CVE-2011-1833, CVE-2011-2492,
  CVE-2011-2689, CVE-2011-2699, CVE-2011-2918
```

### USN-3199-2 (2017-September)

The lines in the `References:` section seems to start with two spaces, but in reality it contains a non-breaking space (U+00A0, 0xC2 0xA0 in UTF-8).

To humans reading the text, this character looks exactly like a space character (0x20), but it's really not, and the regular Java functions like `trim()` and `startsWith()` will produce the wrong output. Even regexes using the `\s` character class will not match this character.

The solution is to replace all whitespace characters, including the Unicode non-breaking space, with a single space character. This is done inside the `readNextLine()` function, so that the replacement is applied to all input lines. The downside of this approach is that, tabs are replaced with a single space character -- but text formatting is not our main concern right now.

```txt
References:
  http://www.ubuntu.com/usn/usn-3199-2
  http://www.ubuntu.com/usn/usn-3199-1
  CVE-2013-7459
```

Note: To be safe, we use this pattern matching method also for the safe versions list.

### USN-3621-1 (2018-April)

CVE split by email wrapping. This is currently not handled

```txt
References:
  https://usn.ubuntu.com/usn/usn-3621-1
  CVE-2018-1000073, CVE-2018-1000074, CVE-2018-1000075, CVE-2018-
1000076,
  CVE-2018-1000077, CVE-2018-1000078, CVE-2018-1000079
```

## Malformed safe versions section

### USN-149-1 (2005-July)

The package name is not spelled out inside the brackets. We just extract whatever is in the brackets and store it.

```txt
The problem can be corrected by upgrading the affected package to
version 1.0.6-0ubuntu0.0.1 (mozilla-firefox) and 1.0.6-0ubuntu0.1
(mozilla-firefox-locale-... packages).
```

### USN-219-1 (2005-November)

Is not conformant to any other rule, and doesn't actually contain information about safe package versions. We cannot extract anything useful from this email.

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)
Ubuntu 5.10 (Breezy Badger)

The following Ubuntu 4.10 packages are affected:

linux-image-2.6.8.1-6-386
linux-image-2.6.8.1-6-686
linux-image-2.6.8.1-6-686-smp
linux-image-2.6.8.1-6-k7
linux-image-2.6.8.1-6-k7-smp
linux-image-2.6.8.1-6-amd64-generic
linux-image-2.6.8.1-6-amd64-k8
linux-image-2.6.8.1-6-amd64-k8-smp
linux-image-2.6.8.1-6-amd64-xeon
linux-image-2.6.8.1-6-power3
linux-image-2.6.8.1-6-power3-smp
linux-image-2.6.8.1-6-power4
linux-image-2.6.8.1-6-power4-smp
linux-image-2.6.8.1-6-powerpc
linux-image-2.6.8.1-6-powerpc-smp
linux-patch-debian-2.6.8.1

The following Ubuntu 5.04 packages are affected:

linux-image-2.6.10-6-386
linux-image-2.6.10-6-686
linux-image-2.6.10-6-686-smp
linux-image-2.6.10-6-k7
linux-image-2.6.10-6-k7-smp
linux-image-2.6.10-6-amd64-generic
linux-image-2.6.10-6-amd64-k8
linux-image-2.6.10-6-amd64-k8-smp
linux-image-2.6.10-6-amd64-xeon
linux-image-2.6.10-6-power3
linux-image-2.6.10-6-power3-smp
linux-image-2.6.10-6-power4
linux-image-2.6.10-6-power4-smp
linux-image-2.6.10-6-powerpc
linux-image-2.6.10-6-powerpc-smp
linux-patch-ubuntu-2.6.10

The following Ubuntu 5.10 packages are affected:

linux-image-2.6.12-10-386
linux-image-2.6.12-10-686
linux-image-2.6.12-10-686-smp
linux-image-2.6.12-10-k7
linux-image-2.6.12-10-k7-smp
linux-image-2.6.12-10-amd64-generic
linux-image-2.6.12-10-amd64-k8
linux-image-2.6.12-10-amd64-k8-smp
linux-image-2.6.12-10-amd64-xeon
linux-image-2.6.12-10-powerpc
linux-image-2.6.12-10-powerpc-smp
linux-image-2.6.12-10-powerpc64-smp
linux-patch-ubuntu-2.6.12

The problem can be corrected by installing the affected package, which
provides a new kernel. Unless you manually uninstalled the standard
kernel metapackages (linux-image-386, linux-image-powerpc, or
linux-image-amd64-generic), this will happen automatically with a
standard system upgrade.

ATTENTION: Due to an unavoidable ABI change this kernel has been given
a new version number, which requires you to recompile and reinstall
all third party kernel modules you might have installed. If you use
linux-restricted-modules, you have to update that package as well to
get modules which work with the new kernel version. Unless you
manually uninstalled the standard kernel metapackages (linux-386,
linux-powerpc, linux-amd64-generic), a standard system upgrade will
automatically perform this as well.

Details follow:
```

### USN-260-1 (2006-March)

The package names have a colon `:`, and there is a blank line between the Ubuntu version line and the package version lines.

```txt
The problem can be corrected by upgrading the affected package to
the following versions:

Ubuntu 4.10:

  flex:         2.5.31-26ubuntu1.2 
  gpc-2.1-3.3:  2:3.3.4.20040516-9ubuntu5.1
  gpc-2.1-3.4:  3.4.2-2ubuntu1.1

Ubuntu 5.04:

  flex:         2.5.31-31ubuntu0.5.04.1
  gpc-2.1-3.3:  2:3.3.5.20040516-8ubuntu2.1
  gpc-2.1-3.4:  3.4.3-9ubuntu4.1

Ubuntu 5.10:

  flex:         2.5.31-31ubuntu0.5.10.1
  gpc-2.1-3.4:  3.4.4-6ubuntu8.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.
```

### USN-612-2 (2008-May)

There is a list of safe versions, but it has a non-standard format, being nested inside a numbered list. We need a special matcher just for this purpose. The `Updating your system:` part is ahead of its time, though.

```txt
Updating your system:

1. Install the security updates

   Ubuntu 7.04:
     openssh-client                  1:4.3p2-8ubuntu1.3
     openssh-server                  1:4.3p2-8ubuntu1.3

   Ubuntu 7.10:
     openssh-client                  1:4.6p1-5ubuntu0.3
     openssh-server                  1:4.6p1-5ubuntu0.3

   Ubuntu 8.04 LTS:
     openssh-client                  1:4.7p1-8ubuntu1.1
     openssh-server                  1:4.7p1-8ubuntu1.1

   Once the update is applied, weak user keys will be automatically
   rejected where possible (though they cannot be detected in all
   cases). If you are using such keys for user authentication,
   they will immediately stop working and will need to be replaced
   (see step 3).
```

### USN-1061-1 (2011-February)

We will ignore non-mainline Ubuntu distros for now

```txt
The problem can be corrected by upgrading your system to the
following package versions:

Edubuntu 9.10:
  italc-client                    1:1.0.9.1-0ubuntu16.1

Edubuntu 10.04 LTS:
  italc-client                    1:1.0.9.1-0ubuntu18.10.04.1

Edubuntu 10.10:
  italc-client                    1:1.0.9.1-0ubuntu18.10.10.1

After a standard system update, if you had originally installed from
the Edubuntu Live DVD and the bad keys were found, you will need to
redistribute the newly generated public keys to your iTALC clients and
restart each session. For more details, see:
https://wiki.ubuntu.com/iTalc/Keys
```

### USN-1709-1 (2013-January)

Some of the package and versions listed in the safe versions section seem to have been text-wrapped because the line is too long. We recognize this and join the lines.

```txt
Update instructions:

The problem can be corrected by updating your system to the following
package versions:

Ubuntu 12.10:
  nova-volume
2012.2.1+stable-20121212-a99a802e-0ubuntu1.1
  python-nova
2012.2.1+stable-20121212-a99a802e-0ubuntu1.1

Ubuntu 12.04 LTS:
  nova-volume
2012.1.3+stable-20120827-4d2a4afe-0ubuntu1.1
  python-nova
2012.1.3+stable-20120827-4d2a4afe-0ubuntu1.1

Ubuntu 11.10:
  nova-volume                     2011.3-0ubuntu6.11
  python-nova                     2011.3-0ubuntu6.11

In general, a standard system update will make all the necessary changes.

References:
```

### USN-2052-1 (2013-December)

The package and version line is indented by 3 spaces instead of the standard 2. This is solved by making the indentation check a bit more lenient.

```txt
Update instructions:

The problem can be corrected by updating your system to the following
package versions:

Ubuntu 13.10:
   firefox                         26.0+build2-0ubuntu0.13.10.2

Ubuntu 13.04:
   firefox                         26.0+build2-0ubuntu0.13.04.2

Ubuntu 12.10:
   firefox                         26.0+build2-0ubuntu0.12.10.2

Ubuntu 12.04 LTS:
   firefox                         26.0+build2-0ubuntu0.12.04.2

After a standard system update you need to restart Firefox to make
all the necessary changes.

References:
```

### USN-3845-1 (2018-December)

The package version line seems to have been wrapped, but the wrapped line is also indented. So when looking for lines to join, we make the indentation optional.

```txt
Update instructions:

The problem can be corrected by updating your system to the 
following package versions:

Ubuntu 18.10:
  libfreerdp-client2-2 
  2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1
  libfreerdp2-2 
  2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1

Ubuntu 18.04 LTS:
  libfreerdp-client2-2 
  2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1
  libfreerdp2-2 
  2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1

Ubuntu 16.04 LTS:
  libfreerdp-client1.1 
  1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3

Ubuntu 14.04 LTS:
  libfreerdp1                     1.0.2-2ubuntu1.2

In general, a standard system update will make all the necessary 
changes.

References:
```

### USN-3845-2 (2019-May)

Sometimes the version line can be broken up by erratic text wrapping.

```txt
Update instructions:

The problem can be corrected by updating your system to the following
package versions:

Ubuntu 18.10:
  libfreerdp-client1.1            1.1.0~git20140921.1.440916e+dfsg1-
15ubuntu1.18.10.1

Ubuntu 18.04 LTS:
  libfreerdp-client1.1            1.1.0~git20140921.1.440916e+dfsg1-
15ubuntu1.18.04.1

In general, a standard system update will make all the necessary
changes.
```

### USN-4246-1 (2020-January)

The indentation is stripped. This email doesn't have any indentation at all.

We may need to do the following:
- make all indentation optional
- to recognize sections:
	- rely on keyword matching, and
	- empty line marking
	- don't relying on indentation

Then the logic would be:
1. In the safe versions section, find the Ubuntu version line
1. Read the next lines until we find an empty line
	- if there is only one word on the line, then it's the package name only, join the next line so we get the version
	- store any package-version pair found
1. Stop when we get a non-Ubuntu version after a blank line

```txt
Update instructions:

The problem can be corrected by updating your system to the following
package versions:

Ubuntu 16.04 LTS:
lib32z1 1:1.2.8.dfsg-2ubuntu4.3
lib64z1 1:1.2.8.dfsg-2ubuntu4.3
libn32z1 1:1.2.8.dfsg-2ubuntu4.3
libx32z1 1:1.2.8.dfsg-2ubuntu4.3
zlib1g 1:1.2.8.dfsg-2ubuntu4.3

In general, a standard system update will make all the necessary changes.

References:
```

## Miscellaneous

### USN-4246-1 (2020-January)

An improper `References:` marker in the email header

```txt
From avital.ostromich at canonical.com  Wed Jan 22 20:54:47 2020
From: avital.ostromich at canonical.com (Avital Ostromich)
Date: Wed, 22 Jan 2020 15:54:47 -0500
Subject: [USN-4246-1] zlib vulnerabilities
In-Reply-To: <20200122190123.BFEF626C265A@lillypilly.canonical.com>
References: <20200122190123.BFEF626C265A@lillypilly.canonical.com>
Message-ID: <3e96c8c8-d037-00bb-d4b0-8a409b7bc07d@canonical.com>

==========================================================================
Ubuntu Security Notice USN-4246-1
January 22, 2020

zlib vulnerabilities
==========================================================================
```
