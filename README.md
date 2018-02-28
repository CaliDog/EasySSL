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

We aimed to make the usage as stupid simple as possible, so there are only 2 exported functions:

### parse_der

Parses a DER-encoded X509 certificate and returns a [Map](https://hexdocs.pm/elixir/Map.html)

```

```