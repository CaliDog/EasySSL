defmodule EasySSLTest do
  use ExUnit.Case

  @der_cert_dir "test/data/der/"
  @pem_cert_dir "test/data/pem/"

  def assert_has_normal_atom_keys(cert) do
    keys = [:extensions, :fingerprint, :not_after, :not_before, :serial_number, :subject]
    Enum.each(keys, fn key ->
      assert Map.has_key?(cert, key)
    end)
  end

  def assert_has_normal_string_keys(cert) do
    keys = ["extensions", "fingerprint", "not_after", "not_before", "serial_number", "subject"]
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

end
