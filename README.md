# `ptt`, a suit of unikernels for SMTP protocols

`ptt` is a suite of unikernels offering several SMTP servers. Currently, two
SMTP servers are available:
- a server capable of managing mailing lists
- a server that allows incoming emails to be signed (DKIM and ARC)

The aim of ptt is to provide a way of deploying an SMTP service (such as a
mailing list) using unikernels. The unikernels are developed using
[Solo5][solo5] and can be deployed using [Albatross][albatross].

## `ptt` as a mailing list

Deploying our SMTP servers requires access to a primary DNS server using a TSIG
key in order to add the necessary records for ARC and DKIM. SPF must be
configured manually. To obtain a TLS certificate for StartTLS communication, use
our Let’s Encrypt unikernel (a secondary DNS server that handles the ACME
challenge). In this way, the SMTP service configuration is described as
_stateless_; the unikernels configure themselves automatically based on the
response from the primary DNS server.

The SMTP server managing the mailing lists requires a _block device_ formatted
as a FAT32 file system. Let's create a new mailing list with:
```shell
$ ptt create lipap.img
$ ptt add lipap.img --domain mailingl.st ptt --moderator foo@bar.com
$ ptt add-moderator lipap.img --domain mailingl.st bar@foo.com
```

You can check the image with `mount`
```shell
$ sudo mount lipap.img /mnt
$ ls /mnt
bounces.json  lists  temp.json  tmp
```

The JSON files in the lists/ folder correspond to the mailing lists
(subscribers, moderators, etc.). The bounces.json file contains the addresses
for which we have encountered an error (it should therefore be empty initially).
The tmp/ folder and temp.json contains emails that need to be resent to certain
destinations where a temporary error occurred.

As a practical example, the mailing list <ptt@mailingl.st> is available for any
questions and/or issues. You can also check https://mailingl.st/.

## Note about DNS configuration

Even though `ptt` configures ARC and DKIM, it does not configure other DNS
records that may be required by other email services. In this case, it is
advisable to:
- add an SPF record `<your-domain>: v=spf1 ip4:<your-public-ipv4>/32 ~all`
- add a DMARC record `_dmarc.<your-domain>: v=DMARC1; p=quarantine;`
- check the reverse DNS
- make your WHOIS information public
