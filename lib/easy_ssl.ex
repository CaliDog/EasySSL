require Logger

defmodule EasySSL do
  @moduledoc """
  EasySSL is a wrapper around Erlang's `:public_key` module to make it far more friendly. It automatically
  processes OIDs for most X509v3 extensions and subject fields.

  There are really only two functions of note - `parse_der` and `parse_pem`, which should have obvious functions.
  """
  @pubkey_schema Record.extract_all(from_lib: "public_key/include/OTP-PUB-KEY.hrl")

  @extended_key_usages %{
    {1,3,6,1,5,5,7,3,1} => "TLS Web server authentication",
    {1,3,6,1,5,5,7,3,2} => "TLS Web client authentication",
    {1,3,6,1,5,5,7,3,3} => "Code signing",
    {1,3,6,1,5,5,7,3,4} => "E-mail protection",
    {1,3,6,1,5,5,7,3,8} => "Timestamping",
    {1,3,6,1,5,5,7,3,9} => "OCSPstamping",
    {1,3,6,1,5,5,7,3,5} => "IP security end system",
    {1,3,6,1,5,5,7,3,6} => "IP security tunnel termination",
    {1,3,6,1,5,5,7,3,7} => "IP security user",
  }

  @authority_info_access_oids %{
    {1,3,6,1,5,5,7,48,1} => "OCSP - URI",
    {1,3,6,1,5,5,7,48,2} => "CA Issuers - URI",
  }

  @doc """
  Takes in a binary (`<<...>>`) and returns a map of the parsed certificate

  ## Examples

      # Pass in a binary (from Base.decode64, or some other source)
      iex(1)> EasySSL.parse_der(<<...>>)
      %{
        extensions: %{
          authorityInfoAccess: "CA Issuers - URI:http://certificates.godaddy.com/repository/gd_intermediate.crt\\nOCSP - URI:http://ocsp.godaddy.com/\\n",
          authorityKeyIdentifier: "keyid:FD:AC:61:32:93:6C:45:D6:E2:EE:85:5F:9A:BA:E7:76:99:68:CC:E7\\n",
          basicConstraints: "CA:FALSE",
          certificatePolicies: "Policy: 2.16.840.1.114413.1.7.23.1\\n  CPS: http://certificates.godaddy.com/repository/",
          crlDistributionPoints: "Full Name:\\n URI:http://crl.godaddy.com/gds1-90.crl",
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
  """
  def parse_der(certificate_der, opts \\ [all_domains: false, serialize: false]) when is_binary(certificate_der) do
    cert = :public_key.pkix_decode_cert(certificate_der, :otp) |> get_field(:tbsCertificate)

    serialized_certificate = %{}
      |> Map.put(:fingerprint, certificate_der |> fingerprint_cert)
      |> Map.put(:serial_number, cert |> get_field(:serialNumber) |> Integer.to_string(16))
      |> Map.put(:subject, cert |> parse_subject)
      |> Map.put(:extensions, cert |> parse_extensions)
      |> Map.merge(parse_expiry(cert))

    Enum.reduce(opts, serialized_certificate, fn {option, flag}, serialized_certificate ->
      case option do
        :all_domains when flag == true ->
          serialized_certificate
            |> Map.put(:all_domains, get_all_domain_names(cert, serialized_certificate))

        :serialize when flag == true ->
          serialized_certificate
            |> Map.put(:as_der, Base.encode64(certificate_der))
        _ -> serialized_certificate
      end
    end)
  end

  def get_all_domain_names(cert, serialized_cert) do
    domain_names = MapSet.new()

    domain_names = case serialized_cert[:subject][:CN] do
      nil -> domain_names
      _ -> MapSet.put(domain_names, serialized_cert[:subject][:CN])
    end

    extensions = cert |> get_field(:extensions)

    extensions
      |> Enum.reduce(domain_names, fn extension, domain_names ->
          case extension do
            {:Extension, {2, 5, 29, 17}, _critical, san_entries} ->
              san_entries
                |> Enum.reduce(domain_names, fn entry, names ->
                  case entry do
                    {:dNSName, dns_name} -> MapSet.put(names, dns_name |> to_string)
                    _ -> names
                  end
                end)
            :asn1_NOVALUE -> domain_names
            _ -> domain_names
          end
        end)
      |> MapSet.to_list
  end

  @doc """
  Takes in a string (or charlist) and returns a map of the parsed certificate

  ## Examples

      # Pass in a binary (from Base.decode64, or some other source)
      iex(1)> EasySSL.parse_pem("-----BEGIN CERTIFICATE-----\\nMII...")
      %{
        extensions: %{
          authorityInfoAccess: "CA Issuers - URI:http://certificates.godaddy.com/repository/gd_intermediate.crt\\nOCSP - URI:http://ocsp.godaddy.com/\\n",
          authorityKeyIdentifier: "keyid:FD:AC:61:32:93:6C:45:D6:E2:EE:85:5F:9A:BA:E7:76:99:68:CC:E7\\n",
          basicConstraints: "CA:FALSE",
          certificatePolicies: "Policy: 2.16.840.1.114413.1.7.23.1\\n  CPS: http://certificates.godaddy.com/repository/",
          crlDistributionPoints: "Full Name:\\n URI:http://crl.godaddy.com/gds1-90.crl",
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
"""
  def parse_pem(cert_charlist) when is_list(cert_charlist) do parse_pem(cert_charlist |> to_string) end
  def parse_pem(cert_pem, opts \\ [all_domains: false, return_base64: false]) do
    cert_regex = ~r/^\-{5}BEGIN\sCERTIFICATE\-{5}\n(?<certificate>[^\-]+)\-{5}END\sCERTIFICATE\-{5}/
    match = Regex.named_captures(cert_regex, cert_pem)

    if match == nil do
      {:error, "Unable to parse PEM. Is the certificate well formed?"}
    else
      match["certificate"]
      |> String.replace("\n", "")
      |> Base.decode64!
      |> parse_der(opts)
    end

  end

  defp get_field(record, field) do
    record_type = elem(record, 0)
    idx = @pubkey_schema[record_type]
          |> Keyword.keys
          |> Enum.find_index(&(&1 == field))

    elem(record, idx + 1)
  end

  defp fingerprint_cert(certificate) do
    :crypto.hash(:sha, certificate)
    |> Base.encode16
    |> String.to_charlist
    |> Enum.chunk_every(2, 2, :discard)
    |> Enum.join(":")
  end

  defp parse_expiry(cert) do
    {:Validity, not_before, not_after} = cert |> get_field(:validity)

    %{
      :not_before => not_before |> to_generalized_time |> asn1_to_epoch,
      :not_after => not_after |> to_generalized_time |> asn1_to_epoch
    }
  end

  defp to_generalized_time({:generalTime, time}), do: time
  defp to_generalized_time({:utcTime, time}) do
    year = time |> Enum.take(2) |> List.to_integer()
    prefix = if year >=  50, do: '19', else: '20'
    prefix ++ time
  end

  defp asn1_to_epoch(asn1_time) do
    {year, rest} = Enum.split(asn1_time, 4)
    date = case rest |> Enum.chunk_every(2) do
      [month, day, hour, minute, second, 'Z'] -> [year, month, day, hour, minute, second]
      [month, day, hour, minute, 'Z'] -> [year, month, day, hour, minute, '00']
      _ ->
        Logger.error("Unhandled ASN1 time structure - #{asn1_time}}")
        nil
    end

    date_args = date |> Enum.map(&(to_string(&1) |> String.to_integer))

    case apply(NaiveDateTime, :new, date_args) do
      {:ok, ~N[9999-12-31 23:59:59]} -> :no_expiration
      {:ok, datetime} -> datetime |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix
      _ ->
        Logger.error("Unhandled ASN1 time structure - #{date_args}}")
        nil
    end
  end

  defp parse_subject(cert) do
    subject = %{
      :CN => nil,
      :C => nil,
      :L => nil,
      :ST => nil,
      :O => nil,
      :OU => nil,
    }

    {:rdnSequence, subject_attribute} = cert |> get_field(:subject)

    subject = subject_attribute |> List.flatten |> Enum.reduce(subject, fn attr, subject ->
      {:AttributeTypeAndValue, oid, attribute_value} = attr

      attr_atom = case oid do
        {2, 5, 4, 3} -> :CN
        {2, 5, 4, 6} -> :C
        {2, 5, 4, 7} -> :L
        {2, 5, 4, 8} -> :ST
        {2, 5, 4, 10} -> :O
        {2, 5, 4, 11} -> :OU
        _ -> nil
      end

      case attr_atom do
        nil -> subject
        _ -> %{subject | attr_atom => attribute_value |> coerce_to_string |> to_string}
      end
    end)

    Map.put(subject, :aggregated, subject |> aggregate_subject)

  end

  defp coerce_to_string(attribute_value) do
    case attribute_value do
      {:printableString, string} -> string
      {:utf8String, string} -> string
      {:teletexString, string} -> string
      string when is_list(string) -> string
      _ ->
        Logger.error("Unhandled subject attribute type #{inspect attribute_value}")
        nil
    end
  end

  defp aggregate_subject(subject) do
    subject
      # Filter out empty values
      |> Enum.filter(fn {_, v} -> v != nil end)
        # Turn everything in to a string so C=blah.com
      |> Enum.map(fn {k, v} -> (k |> to_string) <> "=" <> (v |> to_string) end)
        # Add a buffer to the front to
      |> Enum.join("/")
      |> String.replace_prefix("", "/")
  end

  defp parse_extensions(cert) do
    extensions = cert |> get_field(:extensions)

    case extensions do
      :asn1_NOVALUE -> %{}
      _ ->
        extensions
        |> Enum.reduce(%{}, fn extension, extension_map ->
          case extension do
            {:Extension, {1, 3, 6, 1, 5, 5, 7, 1, 1}, _critical, authority_info_access} ->
              Map.put(
                extension_map,
                :authorityInfoAccess,
                authority_info_access
                |> Enum.reduce([], fn match, entries ->
                  case match do
                    {:AccessDescription, oid, {:uniformResourceIdentifier, url}} -> ["#{@authority_info_access_oids[oid]}:#{url}" | entries]
                    _ -> entries
                  end
                end)
                |> Enum.join("\n")
                |> String.replace_suffix("", "\n")
              )

            {:Extension, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, _critical, sct_data} ->
              Map.put(
                extension_map,
                :ctlSignedCertificateTimestamp,
                Base.url_encode64(sct_data)
              )

            {:Extension, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, _critical, _null_data} ->
              Map.put(
                extension_map,
                :ctlPoisonByte,
                true
              )

            {:Extension, {2, 5, 29, 14}, _critical, subject_key_identifier} ->
              Map.put(
                extension_map,
                :subjectKeyIdentifier,
                subject_key_identifier
                |> Base.encode16
                |> String.to_charlist
                |> Enum.chunk_every(2, 2, :discard)
                |> Enum.join(":")
              )

            {:Extension, {2, 5, 29, 15}, _critical, key_usage} ->
              Map.put(
                extension_map,
                :keyUsage,
                key_usage
                |> join_usage_types
              )

            {:Extension, {2, 5, 29, 17}, _critical, san_entries} ->
              Map.put(
                extension_map,
                :subjectAltName,
                san_entries
                |> Enum.reduce([], fn entry, san_list ->
                  case entry do
                    {:dNSName, dns_name} -> ["DNS:" <> (dns_name |> to_string) | san_list]
                    {:uniformResourceIdentifier, identifier} -> ["URI:" <> (identifier |> to_string) | san_list]
                    {:rfc822Name, identifier} -> ["RFC 822Name:" <> (identifier |> to_string) | san_list]
                    {:iPAddress, ip} -> ["IP:" <> (ip |> ip_to_string) | san_list]

                    # Basically ignore those
                    {:directoryName, _sequence} -> san_list
                    {:otherName, _sequence} -> san_list

                    _ ->
                      Logger.error("Unhandled SAN entry type #{inspect entry}")
                      san_list
                  end
                end)
                |> Enum.join(", ")
              )

            {:Extension, {2, 5, 29, 18}, _critical, issuer_alt_name_entries} ->
              Map.put(
                extension_map,
                :issuerAltName,
                issuer_alt_name_entries
                |> Enum.reduce([], fn entry, issuer_list ->
                  case entry do
                    {:uniformResourceIdentifier, identifier} -> ["URI:" <> (identifier |> to_string) | issuer_list]
                    {:dNSName, dns_name} -> ["DNS:" <> (dns_name |> to_string) | issuer_list]
                    {:rfc822Name, identifier} -> ["RFC 822Name:" <> (identifier |> to_string) | issuer_list]
                    {:iPAddress, ip} -> ["IP:" <> (ip |> ip_to_string) | issuer_list]

                    # Ignore these
                    {:directoryName, _sequence} -> issuer_list
                    {:otherName, _sequence} -> issuer_list

                    _ ->
                      Logger.error("Unhandled IAN entry type #{inspect entry}")
                      issuer_list
                  end
                end)
                |> Enum.join(", ")
              )

            {:Extension, {2, 5, 29, 19}, _critical, {:BasicConstraints, is_ca, _max_pathlen}} ->
              Map.put(
                extension_map,
                :basicConstraints,
                case is_ca do
                  true -> "CA:TRUE"
                  false -> "CA:FALSE"
                end
              )

            {:Extension, {2, 5, 29, 31}, _critical, crl_distribution_points} ->
              Map.put(
                extension_map,
                :crlDistributionPoints,
                crl_distribution_points
                |> Enum.reduce([], fn distro_point, output ->
                  case distro_point do
                    {:DistributionPoint, {:fullName, crls}, :asn1_NOVALUE, :asn1_NOVALUE} ->
                      crl_string =
                        crls
                        |> Enum.map(fn identifier ->
                          case identifier do
                            {:uniformResourceIdentifier, uri} ->
                              " URI:#{uri}"
                            {:rfc822Name, identifier} -> " RFC 822 Name: #{identifier}"
                            {:directoryName, _rdn_sequence} ->
                              "" # Just skip this for now, not commonly used.
                          end
                        end)
                        |> Enum.join("\n")

                      output = ["Full Name:" | output]
                      output = [crl_string | output]
                      output
                      |> Enum.reverse()

                    _ ->
                      Logger.error("Unhandled CRL distrobution point #{inspect distro_point}")
                      output
                  end
                end)
                |> Enum.join("\n")
              )

            {:Extension, {2, 5, 29, 32}, _critical, policy_entries} ->
              Map.put(
                extension_map,
                :certificatePolicies,
                policy_entries
                |> List.flatten
                |> Enum.reduce([], fn entry, policy_entries ->
                  case entry do
                    {:PolicyInformation, oid, :asn1_NOVALUE} ->
                      ["Policy: #{oid |> Tuple.to_list |> Enum.join(".")}" | policy_entries]

                    {:PolicyInformation, oid, policy_information} ->
                      oid_string = oid
                                   |> Tuple.to_list
                                   |> Enum.join(".")
                                   |> String.replace_prefix("", "Policy: ")

                      message = [oid_string]

                      policy_information
                      |> Enum.reduce(message, fn policy, message ->
                        case policy do
                          {:PolicyQualifierInfo, {1, 3, 6, 1, 5, 5, 7, 2, 1}, cps_data} ->
                            cps_string = cps_data
                                         |> to_charlist
                                         |> Enum.drop(2)
                                         |> to_string
                                         |> String.replace_prefix("", "  CPS: ")
                            [cps_string | message]

                          {:PolicyQualifierInfo, {1, 3, 6, 1, 5, 5, 7, 2, 2}, user_notice_data} ->
                            <<_::binary-size(8), user_notice::binary>> = user_notice_data

                            user_notice = user_notice
                              |> String.codepoints
                              |> Enum.filter(fn(c) -> String.printable?(c) end)
                              |> Enum.join("")
                              |> String.replace_prefix("", "  User Notice: ")

                            [user_notice  | message]

                        end
                      end)
                      |> Enum.reverse
                  end
                end)
                |> Enum.join("\n")
              )

            {:Extension, {2, 5, 29, 35}, _critical, {:AuthorityKeyIdentifier, authority_key_identifier, _, _}} ->
              case authority_key_identifier do
                value when is_binary(value) ->
                  Map.put(
                    extension_map,
                    :authorityKeyIdentifier,
                    authority_key_identifier
                    |> Base.encode16
                    |> String.to_charlist
                    |> Enum.chunk_every(2, 2, :discard)
                    |> Enum.join(":")
                    |> String.replace_prefix("", "keyid:")
                    |> String.replace_suffix("", "\n")
                  )
                :asn1_NOVALUE -> extension_map

              end

            {:Extension, {2, 5, 29, 37}, _critical, extended_key_usage} ->
              Map.put(
                extension_map,
                :extendedKeyUsage,
                extended_key_usage
                |> Enum.map(&(@extended_key_usages[&1]))
                |> Enum.join(", ")
              )

            {:Extension, oid, _critical, _payload} ->
              Map.put_new(extension_map, :extra, [])
              |> Map.update!(:extra, fn x ->
                [oid |> Tuple.to_list |> Enum.join(".") | x]
              end)
          end
        end)
    end
  end

  defp ip_to_string(ip) do
    ip
      |> :binary.bin_to_list
      |> Enum.map(&to_string/1)
      |> Enum.join(".")
  end

  defp join_usage_types(key_usage) do
    key_usage
    |> Enum.reduce([], fn usage_atom, output ->
      [usage_atom |> camel_to_spaces | output]
    end)
    |> Enum.reverse
    |> Enum.join(", ")
  end

  defp camel_to_spaces(atom) do
    atom
    |> Atom.to_charlist
    |> Enum.reduce([], fn char, charlist ->
      charlist = [char | charlist]
      case char in 65..90 do
        true -> List.insert_at(charlist, 1, ' ')
        false -> charlist
      end
    end)
    |> Enum.reverse
    |> to_string
    |> String.split
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

end
