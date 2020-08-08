defmodule EasySSLTest do
  use ExUnit.Case

  @der_cert_dir "test/data/der/"
  @pem_cert_dir "test/data/pem/"

  def assert_has_normal_atom_keys(cert) do
    keys = [:extensions, :fingerprint, :issuer, :not_after, :not_before, :serial_number, :subject]
    Enum.each(keys, fn key ->
      assert Map.has_key?(cert, key)
    end)
  end

  def assert_has_normal_string_keys(cert) do
    keys = ["extensions", "fingerprint", "issuer", "not_after", "not_before", "serial_number", "subject"]
    Enum.each(keys, fn key ->
      assert Map.has_key?(cert, key)
    end)
  end

  test "parses all certifiates in @der_cert_dir directory" do
    File.ls!(@der_cert_dir)
      |> Enum.each(fn cert_filename ->
            original_cert = File.read!(@der_cert_dir <> cert_filename)
              |> EasySSL.parse_der

            reparsed_cert = original_cert
              |> Poison.encode!
              |> Poison.decode!
            assert_has_normal_atom_keys(original_cert)
            assert_has_normal_string_keys(reparsed_cert)
         end)
  end

  test "parses all certifiates in @pem_cert_dir directory" do
    File.ls!(@pem_cert_dir)
    |> Enum.each(fn cert_filename ->
      original_cert = File.read!(@pem_cert_dir <> cert_filename)
                      |> EasySSL.parse_pem

      reparsed_cert = original_cert
                      |> Poison.encode!
                      |> Poison.decode!
      assert_has_normal_atom_keys(original_cert)
      assert_has_normal_string_keys(reparsed_cert)
    end)
  end

  test "parses a pem charlist properly" do
    cert =
      File.ls!(@pem_cert_dir)
        |> Enum.at(0)
        |> (&(File.read!(@pem_cert_dir <> &1))).()
        |> to_charlist
        |> EasySSL.parse_pem

    assert_has_normal_atom_keys(cert)
  end

  test "parses and adds all domains to the top level leaf node" do
    cert_bytes = File.read!(@der_cert_dir <> "twitter.com.der")

    serialized_cert = cert_bytes
      |> EasySSL.parse_der()
    refute Enum.member?(Map.keys(serialized_cert), :as_der)
    refute Enum.member?(Map.keys(serialized_cert), :all_domains)

    serialized_cert = cert_bytes
      |> EasySSL.parse_der(all_domains: true)
    refute Enum.member?(Map.keys(serialized_cert), :as_der)
    assert Enum.member?(Map.keys(serialized_cert), :all_domains)

    serialized_cert = cert_bytes
      |> EasySSL.parse_der(serialize: true)
    assert Enum.member?(Map.keys(serialized_cert), :as_der)
    refute Enum.member?(Map.keys(serialized_cert), :all_domains)

    serialized_cert = cert_bytes
      |> EasySSL.parse_der(serialize: true, all_domains: true)
    assert Enum.member?(Map.keys(serialized_cert), :as_der)
    assert Enum.member?(Map.keys(serialized_cert), :all_domains)
  end

  test "validity not after the end of year 9999 means no expiration" do
    cert = File.read!(@pem_cert_dir <> "device-cert.crt") |> EasySSL.parse_pem()
    assert Map.has_key?(cert, :not_after)
    assert cert.not_after == :no_expiration
  end

  test "parses validity dates correctly" do
    cert = File.read!(@pem_cert_dir <> "github.com.crt") |> EasySSL.parse_pem()
    assert Map.has_key?(cert, :not_before)
    assert Map.has_key?(cert, :not_after)

    {:ok, correct_before, _offset} = DateTime.from_iso8601("2013-06-10T00:00:00Z")
    {:ok, correct_after, _offset} = DateTime.from_iso8601("2015-09-02T12:00:00Z")
    {:ok, actual_before} = DateTime.from_unix(cert.not_before)
    {:ok, actual_after} = DateTime.from_unix(cert.not_after)

    assert actual_before == correct_before
    assert actual_after == correct_after
  end

  test "parses subject and issuer correctly" do
    cert = File.read!(@pem_cert_dir <> "github.com.crt") |> EasySSL.parse_pem()
    assert Map.has_key?(cert, :subject)
    assert Map.has_key?(cert, :issuer)

    assert cert.subject.aggregated == "/C=US/CN=github.com/L=San Francisco/O=GitHub, Inc./ST=California"
    assert cert.issuer.aggregated == "/C=US/CN=DigiCert High Assurance EV CA-1/O=DigiCert Inc/OU=www.digicert.com"
  end

end
