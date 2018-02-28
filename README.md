# EasySSL

Originally this module was part of the [certstream](https://certstream.calidog.io) project, but we decided that it'd be more useful as a stand-alone module to hopefully de-duplicate the annoyances of figuring out how to use Erlang's `:public_key` module to properly parse X509 certificates and coerce things like extensions and subjects to something that more closely resembles certificate parsing in other languages.

As a forewarning, this is by no means an all-inclusive library for parsing X509 certificates, it's just what we needed as part of our project, but pull requests are extremely welcome if you notice some breakage or ways to improve!

## Installation

As with most libraries in the Elixir landscape, you can install this by adding the following to your deps in `mix.exs`:

```
{:easy_ssl, "~> 1.0.0"}
```

Then run `$ mix deps.get` to fetch the dependency.

Hex docs can be found at [https://hexdocs.pm/easy_ssl](https://hexdocs.pm/easy_ssl).

## Usage

We aim to make the usage as stupid simple as possible, so there are only 2 exported functions (for now), both of which return the following data structure:

```elixir
%{
  extensions: %{
    authorityInfoAccess: "CA Issuers - URI:http://certificates.godaddy.com/repository/gd_intermediate.crt\nOCSP - URI:http://ocsp.godaddy.com/\n",
    authorityKeyIdentifier: "keyid:FD:AC:61:32:93:6C:45:D6:E2:EE:85:5F:9A:BA:E7:76:99:68:CC:E7\n",
    basicConstraints: "CA:FALSE",
    certificatePolicies: "Policy: 2.16.840.1.114413.1.7.23.1\n  CPS: http://certificates.godaddy.com/repository/",
    crlDistributionPoints: "Full Name:\n URI:http://crl.godaddy.com/gds1-90.crl",
    extendedKeyUsage: "TLS Web server authentication, TLS Web client authentication",
    keyUsage: "Digital Signature, Key Encipherment",
    subjectAltName: "DNS:acaline.com, DNS:www.acaline.com",
    subjectKeyIdentifier: "E6:61:14:4E:5A:4B:51:0C:4E:6C:5E:3C:79:61:65:D4:BD:64:94:BE"
  },
  fingerprint: "FA:BE:B5:9B:ED:C2:2B:42:7E:B1:45:C8:9A:8A:73:16:4A:A0:10:09",
  not_after: 1398523877,
  not_before: 1366987877,
  serial_number: "27ACAE30B9F323",
  subject: %{
    C: nil,
    CN: "www.acaline.com",
    L: nil,
    O: nil,
    OU: "Domain Control Validated",
    ST: nil,
    aggregated: "/CN=www.acaline.com/OU=Domain Control Validated"
  }
}
```

### parse_der

Parses a DER-encoded X509 certificate

```elixir
iex(1)> File.read!("some_cert.der") |> EasySSL.parse_der
%{
  extensions: %{
    ...SNIP...
  },
  fingerprint: "FA:BE:B5:9B:ED:C2:2B:42:7E:B1:45:C8:9A:8A:73:16:4A:A0:10:09",
  not_after: 1398523877,
  not_before: 1366987877,
  serial_number: "27ACAE30B9F323",
  subject: %{
    ...SNIP...
  }
}

```

### parse_pem

Parses a PEM-encoded X509 certificate

```elixir
iex(1)> File.read!("some_cert.pem") |> EasySSL.parse_pem
%{
  extensions: %{
    ...SNIP...
  },
  fingerprint: "FA:BE:B5:9B:ED:C2:2B:42:7E:B1:45:C8:9A:8A:73:16:4A:A0:10:09",
  not_after: 1398523877,
  not_before: 1366987877,
  serial_number: "27ACAE30B9F323",
  subject: %{
    ...SNIP...
  }
}

```



If you'd like some other functionality or find a bug please open a ticket!
