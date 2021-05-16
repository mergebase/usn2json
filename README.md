# usn2json

This tool reads mail archives from ubuntu-security-archive, then converts the contents to JSON.

## Notes for parsing and collecting data from emails

### 2004-October (1)

This is the very beginning of the mailing list. These data can be readily parsed:
- start of the email itself, by the initial `from xxx` line
- `message-id`
- `id`
- `date`
- `project`

These data can be parsed, with some caveats as described below:
- `cves`
- `safeVersions`

No concise `description` can be parsed, until [2011-April](#2011-april).

### 2004-October (2)

CAN's can be collected from a special section immediately after `Message-ID:`.

```txt
===========================================================
Ubuntu Security Notice 1-1                 October 22, 2004
PNG library vulnerabilities
CAN-2004-0955
===========================================================
```

CAN's are not limited to a single line, like this:

```txt
===========================================================
Ubuntu Security Notice USN-38-1           December 14, 2004
linux-source-2.6.8.1 vulnerabilities
CAN-2004-0814, CAN-2004-1016, CAN-2004-1056, CAN-2004-1058, 
CAN-2004-1068, CAN-2004-1069, CAN-2004-1137, CAN-2004-1151
===========================================================
```

### 2004-October (3)

Information about safe package versions need to be extracted from a special textual paragraph.

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

mozilla-thunderbird
mozilla-thunderbird-enigmail

The problem can be corrected by upgrading the affected package to
version 1.0.6-0ubuntu04.10 (for Ubuntu 4.10), or 1.0.6-0ubuntu05.04
(for Ubuntu 5.04).  You need to restart Thunderbird after a standard
system upgrade to effect the necessary changes.

The current Enigmail plugin is not compatible any more with the
Thunderbird version shipped in this security update, so the
mozilla-thunderbird-enigmail package needs to be updated as well. An
update is already available for Ubuntu 5.04, and will be delivered
shortly for Ubuntu 4.10.


Details follow:
```

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)

The following packages are affected:

libpng12-0
libpng12-dev
libpng10-0
libpng10-dev

The problem can be corrected by upgrading the affected package to version
1.2.5.0-7ubuntu1 (libpng12-0 and libpng12-dev) or 1.0.15-6ubuntu1
(libpng10-0 and libpng10-dev).  In general, a standard system upgrade is
sufficient to effect the necessary changes.

Details follow:
```

### 2005-May

The architecture name is spelled out inside the brackets -- we just ignore them.

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

openoffice.org-bin
openoffice.org-l10n-xh

The problem can be corrected by upgrading the affected package to
version 1.1.2-2ubuntu6.1 (for Ubuntu 4.10 on i386 and powerpc),
1.1.2-2ubuntu6.1-1 (for Ubuntu 4.10 on amd64), 1.1.3-8ubuntu2.3 (for
Ubuntu 5.04 on i386 and powerpc), or 1.1.3-8ubuntu2.3-1 (for Ubuntu
5.04 on amd64).  In general, a standard system upgrade is sufficient
to effect the necessary changes.
```

### 2005-July

During 2005, some emails have this format:

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

libapache2-mod-php4
php4-pear

The problem can be corrected by upgrading the affected package to
version 4:4.3.8-3ubuntu7.9 (for Ubuntu 4.10), or 4:4.3.10-10ubuntu3.1
(for Ubuntu 5.04).  In general, a standard system upgrade is
sufficient to effect the necessary changes.

Details follow:
```

### 2005-August (1)

During 2005, some emails have this format:
- starts with `On Ubuntu`
- more than one paragraph
- more than 2 versions per paragraph
- sometimes have spaces next to brackets

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

gnumeric
python2.1
python2.2
python2.3

On Ubuntu 4.10, the problem can be corrected by upgrading the affected
package to version 1.2.13-1ubuntu2.1 (gnumeric), 2.1.3-24.ubuntu0.1
(python2.1), 2.2.3-10.ubuntu0.2 (python2.2), and 2.3.4-2.ubuntu0.2
(python2.3).

On Ubuntu 5.04, the problem can be corrected by upgrading the affected
package to version 1.4.2-1ubuntu3.1 (gnumeric), 2.2.3dfsg-1ubuntu0.1
(python2.2),  and 2.3.5-2ubuntu0.1 (python2.3).  

After performing a standard system upgrade you need to restart
gnumeric and all python server applications to effect the necessary
changes.


Details follow:
```

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

kerberos4kth-clients
krb5-clients
krb5-kdc
krb5-rsh-server
krb5-telnetd

On Ubuntu 4.10, the problem can be corrected by upgrading the affected
package to version 1.2.2-10ubuntu0.1 (kerberos4kth-clients), and
1.3.4-3ubuntu0.2 (krb5-clients, krb5-kdc, krb5-rsh-server,
krb5-telnetd).

On Ubuntu 5.04, the problem can be corrected by upgrading the affected
package to version 1.2.2-10ubuntu0.1 (kerberos4kth-client ), and
1.3.6-1ubuntu0.1 (krb5-clients, krb5-kdc, krb5-rsh-server,
krb5-telnetd).  

In general, a standard system upgrade is sufficient to effect the
necessary changes.

Details follow:
```

### 2005-August (2)

Sometimes the information inside the brackets override the previous listed info.

```txt
A security issue affects the following Ubuntu releases:

Ubuntu 4.10 (Warty Warthog)
Ubuntu 5.04 (Hoary Hedgehog)

The following packages are affected:

xpdf-reader
xpdf-utils
kpdf

The problem can be corrected by upgrading the affected package to
version 3.00-8ubuntu1.5 (for Ubuntu 4.10), or 3.00-11ubuntu3.1
(xpdf-reader and xpdf-utils for Ubuntu 5.04) and 4:3.4.0-0ubuntu3.1
(kpdf for Ubuntu 5.04).  In general, a standard system upgrade is
sufficient to effect the necessary changes.
```

### 2005-October

CVE's start to replace CAN's.

### 2006-May

Safe versions can be collected by: 
1. first looking for a line that starts with `The problem can be corrected by`, and then
1. looking for a line that starts with `Ubuntu`

And we can stop when we find a line that is:
- not blank, and
- doesn't start with spaces, and
- doesn't start with `Ubuntu`

```txt
The problem can be corrected by upgrading the affected packages to the
following versions:

Ubuntu 5.04:
  postgresql:           7.4.7-2ubuntu2.3
  postgresql-client:    7.4.7-2ubuntu2.3
  postgresql-contrib:   7.4.7-2ubuntu2.3
  libpq3:               7.4.7-2ubuntu2.3
  python2.3-pgsql:      2.4.0-5ubuntu2.1
  python2.4-pgsql:      2.4.0-5ubuntu2.1
  python2.3-psycopg:    1.1.18-1ubuntu5.1
  python2.4-psycopg:    1.1.18-1ubuntu5.1

Ubuntu 5.10:
  postgresql-7.4:               1:7.4.8-17ubuntu1.3
  postgresql-client-7.4:        1:7.4.8-17ubuntu1.3
  postgresql-contrib-7.4:       1:7.4.8-17ubuntu1.3
  libpq3:                       1:7.4.8-17ubuntu1.3
  postgresql-8.0:               8.0.3-15ubuntu2.2
  postgresql-client-8.0:        8.0.3-15ubuntu2.2
  postgresql-contrib-8.0:       8.0.3-15ubuntu2.2
  libpq4:                       8.0.3-15ubuntu2.2
  python2.3-pgsql:              2.4.0-6ubuntu1.1
  python2.4-pgsql:              2.4.0-6ubuntu1.1
  python2.3-psycopg:            1.1.18-1ubuntu6.1
  python2.4-psycopg:            1.1.18-1ubuntu6.1

In general, a standard system upgrade is sufficient to effect the
```

### 2011-April

`Summary:` section now available, ending in a blank line:

```txt
Summary:

An attacker could send crafted input to Konqueror to view sensitive
information.

Software Description:
```

### 2011-April (2)

CVE's can be collected from `References:` section, which ends in a blank line. There are two forms:

- not separated by a comma

```txt
References:
  CVE-2010-3776 CVE-2010-3778 CVE-2011-0053 CVE-2011-0062 CVE-2011-0051 CVE-2011-0055 CVE-2011-0054 CVE-2011-0056 CVE-2011-0057 CVE-2011-0058 CVE-2010-1585 CVE-2011-0059 CVE-2011-0069 CVE-2011-0070 CVE-2011-0080 CVE-2011-0074 CVE-2011-0075 CVE-2011-0077 CVE-2011-0078 CVE-2011-0072 CVE-2011-0065 CVE-2011-0066 CVE-2011-0073 CVE-2011-0067 CVE-2011-0071 CVE-2011-1202

Package Information:
```

- separated by a comma (standardized till now)

```txt
References:
  CVE-2010-2954, CVE-2010-2955, CVE-2010-2960, CVE-2010-2962,
  CVE-2010-2963, CVE-2010-3079, CVE-2010-3080, CVE-2010-3081,
  CVE-2010-3437, CVE-2010-3705, CVE-2010-3848, CVE-2010-3849,
  CVE-2010-3850, CVE-2010-3861, CVE-2010-3865, CVE-2010-3873,
  CVE-2010-3875, CVE-2010-3876, CVE-2010-3877, CVE-2010-3904,
  CVE-2010-4072, CVE-2010-4079, CVE-2010-4158, CVE-2010-4164,
  CVE-2010-4165, CVE-2010-4249, CVE-2010-4342, CVE-2010-4346,
  CVE-2010-4527, CVE-2010-4529

Package Information:
```

### 2011-May

Safe versions can be collected from the `Update instructions:` section, by looking for a line that starts with `Ubuntu`, and stopping when we find a:
- non-blank line, that
- doesn't start with spaces, and
- doesn't start with `Ubuntu`

```txt
Update instructions:

The problem can be corrected by updating your system to the following
package versions:

Ubuntu 11.04:
  usb-creator-common              0.2.28.3

Ubuntu 10.10:
  usb-creator-common              0.2.25.3

Ubuntu 10.04 LTS:
  usb-creator-common              0.2.22.3

In general, a standard system update will make all the necessary changes.
```
