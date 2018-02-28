defmodule EasySSLTest do
  use ExUnit.Case

  @der_cert_dir "test/data/der/"
  @pem_cert_dir "test/data/pem/"

  def assert_has_normal_keys(cert) do
    keys = [:extensions, :fingerprint, :not_after, :not_before, :serial_number, :subject]
    Enum.each(keys, fn key -> assert Map.has_key?(cert, key) end)
  end

  test "parses all certifiates in @der_cert_dir directory" do
    keys = [:extensions, :fingerprint, :not_after, :not_before, :serial_number, :subject]

    File.ls!(@der_cert_dir)
      |> Enum.each(fn cert_filename ->
            cert = File.read!(@der_cert_dir <> cert_filename)
              |> EasySSL.parse_der
            Enum.each(keys, fn key -> assert Map.has_key?(cert, key) end)
         end)
  end

  test "parses all certifiates in @pem_cert_dir directory" do
    File.ls!(@pem_cert_dir)
    |> Enum.each(fn cert_filename ->
      cert = File.read!(@pem_cert_dir <> cert_filename)
              |> EasySSL.parse_pem
      assert_has_normal_keys(cert)
    end)
  end

  test "parses a pem charlist properly" do
    cert =
      File.ls!(@pem_cert_dir)
        |> Enum.at(0)
        |> (&(File.read!(@pem_cert_dir <> &1))).()
        |> to_charlist
        |> EasySSL.parse_pem

    assert_has_normal_keys(cert)
  end

end
