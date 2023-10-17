//
//  CertificateDecoderTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import ShieldOID
import ShieldX509
import PotentASN1
import XCTest


class CertificateDecoderTests: XCTestCase {

  static let outputEnabled = false

  func testDecodingTestCerts() throws {

    for (title, pem) in Self.certificates {
      output("Checking: \(title)")
      guard let testCert = try SecCertificate.load(pem: pem).first else {
        XCTFail("Failed to load '\(title)'")
        continue
      }
      do {
        let decoded = try ASN1.Decoder.decode(Certificate.self, from: testCert.derEncoded)
        let subjectName = try NameStringComposer().append(rdnSequence: decoded.tbsCertificate.subject).string
        output("Version: \(decoded.tbsCertificate.version)")
        output("Serial Number: \(decoded.tbsCertificate.serialNumber.magnitude.serialize())")
        output("Subject: \(subjectName)")
        let issuerName = try NameStringComposer().append(rdnSequence: decoded.tbsCertificate.issuer).string
        output("Issuer: \(issuerName)")
        output("Validity:")
        output("  Not Before:  \(decoded.tbsCertificate.validity.notBefore.zonedDate.iso8601EncodedString())")
        output("  Not After:  \(decoded.tbsCertificate.validity.notAfter.zonedDate.iso8601EncodedString())")

        for ext in decoded.tbsCertificate.extensions ?? [] {
          output("Extension:")
          switch ext.extnID {
          case iso_itu.ds.certificateExtension.basicConstraints.oid:
            let basicContstraints = try ASN1Decoder.decode(BasicConstraints.self, from: ext.extnValue)
            output("  \(basicContstraints)")

          case iso_itu.ds.certificateExtension.extKeyUsage.oid:
            let extKeyUsage = try ASN1Decoder.decode(ExtKeyUsage.self, from: ext.extnValue)
            output("  \(extKeyUsage)")

          case iso_itu.ds.certificateExtension.subjectKeyIdentifier.oid:
            let subjKeyId = try ASN1Decoder.decode(SubjectKeyIdentifier.self, from: ext.extnValue)
            output("  \(subjKeyId)")

          case iso_itu.ds.certificateExtension.authorityKeyIdentifier.oid:
            let authKeyId = try ASN1Decoder.decode(AuthorityKeyIdentifier.self, from: ext.extnValue)
            output("  \(authKeyId)")

          case iso_itu.ds.certificateExtension.subjectAltName.oid:
            let subjectAltName = try ASN1Decoder.decode(SubjectAltName.self, from: ext.extnValue)
            output("  \(subjectAltName)")

          case iso_itu.ds.certificateExtension.issuerAltName.oid:
            let issuerAltName = try ASN1Decoder.decode(IssuerAltName.self, from: ext.extnValue)
            output("  \(issuerAltName)")

          case let oid:
            output("  Unknown: \(oid)")
          }
        }
      }
      catch {
        XCTFail("Failed: \(error.localizedDescription)")
      }

    }
  }

  static let certificates = [
    "Apple": """
    -----BEGIN CERTIFICATE-----
    MIIGpjCCBkugAwIBAgIQKJx5JD51vHmvWQd4OD7NzDAKBggqhkjOPQQDAjBRMQsw
    CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBwbGUg
    UHVibGljIEVWIFNlcnZlciBFQ0MgQ0EgMSAtIEcxMB4XDTIyMDQxOTE2MDUxNFoX
    DTIzMDUxOTE2MDUxM1owgfExHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9u
    MRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQITCkNhbGlmb3Ju
    aWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs
    aWZvcm5pYTESMBAGA1UEBxMJQ3VwZXJ0aW5vMRMwEQYDVQQKEwpBcHBsZSBJbmMu
    MSUwIwYDVQQLExxtYW5hZ2VtZW50OmlkbXMuZ3JvdXAuNjY1MDM1MRkwFwYDVQQD
    ExBpbWFnZXMuYXBwbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEipqG
    cwwgDSIc04hxl4uQTMnkOCDWzr8VfcYiAFqKMiA6Y1cuSnPjoZI7CALLDjZJMD3k
    fUsPBG7wHmvNRHzAoKOCBGIwggReMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
    4IVIfROm0xAZn1zLa3gkkviuG64wegYIKwYBBQUHAQEEbjBsMDIGCCsGAQUFBzAC
    hiZodHRwOi8vY2VydHMuYXBwbGUuY29tL2FwZXZzZWNjMWcxLmRlcjA2BggrBgEF
    BQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcGV2c2VjYzFnMTAx
    MBsGA1UdEQQUMBKCEGltYWdlcy5hcHBsZS5jb20wggESBgNVHSAEggEJMIIBBTAH
    BgVngQwBATCB+QYJYIZIAYb9bAIBMIHrMD4GCCsGAQUFBwIBFjJodHRwczovL3d3
    dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvcHVibGljLzCBqAYIKwYB
    BQUHAgIwgZsMgZhSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBw
    YXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcgUGFydHkgQWdy
    ZWVtZW50IGZvdW5kIGF0IGh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0
    ZWF1dGhvcml0eS9wdWJsaWMvLjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
    AwEwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5hcHBsZS5jb20vYXBldnNl
    Y2MxZzEuY3JsMB0GA1UdDgQWBBQeaqBRkKzrOYrGlikf46YzaU5WpDAOBgNVHQ8B
    Af8EBAMCB4AwggH3BgorBgEEAdZ5AgQCBIIB5wSCAeMB4QB2ALvZ37wfinG1k5Qj
    l6qSe0c4V5UKq1LoGpCWZDaOHtGFAAABgEKbSRUAAAQDAEcwRQIhAI1x8dlzc4sI
    +tekm5BTwmymwxZcg0AIqgXqgXBSRkyWAiAqC4/OqLssOjzQc3PAF+vnaydgda1M
    Ogt+sF9d2lCn/QB3AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAAB
    gEKbSRYAAAQDAEgwRgIhAIPUQ4CH6jhWcTrnmjbOw4N+iRwm10LkpsA/SnuAdUtN
    AiEA7kVKU413xOctBAYcgpj5WZRXJ4HE5MG5/Gg+j6YZoiEAdgB6MoxU2LcttiDq
    OOBSHumEFnAyE4VNO9IrwTpXo1LrUgAAAYBCm0lRAAAEAwBHMEUCIFNKhLMB3i6k
    NfHrfoN+dhRoZZrh+FSwscHvnYbC3phAAiEAvoneV6lqyKicUd7/zArHOns6IXZd
    l4sQIEkbsCVf6AIAdgCt9776fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAA
    AYBCm0k7AAAEAwBHMEUCIE3TT2/uhFmrgfprb0hewqsCRw7RT7kVUhVwT/E11o8l
    AiEA3kgU/SGMqu+74BHllW1+P2ZcePAuefqxEFNvFlgkVAgwCgYIKoZIzj0EAwID
    SQAwRgIhAK1YRIj06iciVrN8yJWO0JTB+/d/XJDXDX8eGu0io3StAiEAoqyVS1Tm
    A9qxgk2DsibWyckLQn5CAk+ypmA/zQ4H79M=
    -----END CERTIFICATE-----

    """,
    "Unknown DirectoryName Value In Subject": """
    -----BEGIN CERTIFICATE-----
    MIICuDCCAl+gAwIBAgIUecq5PxPhG0G7IUS0haBAoc7y4NAwCgYIKoZIzj0EAwIw
    QjEfMB0GA1UEAxMWNVdiUVRyTEp4Vzk2b3VJMXZUTkNhYjEfMB0GA1UEBRMWNVdi
    UVRyTEp4Vzk2b3VJMXZUTkNhYjAeFw0yMzAyMTcxOTAzMzZaFw0yNTAyMTYxOTA0
    MDZaMEQxGjAYBgNVBAMTEUFjY291bnQgQXV0aG9yaXR5MSYwJAYKCZImiZPyLGQB
    ARMWNTRqZlJ4Mnczc1dtMnFaWDNsYzlKWjCCASIwDQYJKoZIhvcNAQEBBQADggEP
    ADCCAQoCggEBAMoYg6ZNef+Yp0JuSP3RKwOLfTKTAeYM45H29laCFf4ZHzOPgn09
    UfMJrJMf+eT4Y8GIObUdY6uxxduKY4zBWW8YftJB9UvYzBsNKJr20ExUBt0Kxhzw
    1tw/OwM6Hv63383TAKc8v3bkt2iDg+QGsxcbqzL65op3Zg1MqiUuaiA+cOr2OQPo
    CTOn6cv6P9bNXtdp9NvvJZtbcPd34axRZXsIcPdxwhPzkjrMTqneMqj0udfL29hZ
    26DT0j5VjuPlidFKxnLbc+315rNQWxzdamyf+DqmiareL+3AK2veo1BUroOcFHTj
    YDj+EN5esVTTfoLu6tBcOPfyGVDf8ZGnmI8CAwEAAaNmMGQwEgYDVR0TAQH/BAgw
    BgEB/wIBAjAdBgNVHQ4EFgQUiVfK6Mmh6pmGog2nNMyr+zah0P8wHwYDVR0jBBgw
    FoAU8y/DPvAeAeduSykhBzpA+5xpH1swDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49
    BAMCA0cAMEQCIHW0xsfuRCoXlB8waIsU275h0dNaVSbQlRayYTCuyqW4AiB6NaW9
    i5BbMGdCIXEpuk0rGyGLYaTHDtJ4X6Epi2379g==
    -----END CERTIFICATE-----

    """,
    "Example 512b": """
    -----BEGIN CERTIFICATE-----
    MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
    A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
    MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
    YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
    ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
    CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
    ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
    8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
    AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
    8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy
    2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0
    Hn+GmxZA
    -----END CERTIFICATE-----

    """,
    "Example 1024b": """
    -----BEGIN CERTIFICATE-----
    MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
    A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
    MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
    YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
    ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
    CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
    ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD
    +6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9
    MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1
    C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ
    kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf
    jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr
    evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=
    -----END CERTIFICATE-----

    """,
  ]

  func output(_ value: String) {
    guard Self.outputEnabled else { return }
    print(value)
  }

  func output(_ value: Encodable & SchemaSpecified) {
    guard Self.outputEnabled else { return }
    guard let data = try? value.encoded().base64EncodedString() else { return }
    output(data)
  }

}
