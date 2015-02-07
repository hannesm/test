

let cert = "-----BEGIN CERTIFICATE-----\nMIIEgjCCAmqgAwIBAgICEAQwDQYJKoZIhvcNAQEMBQAwXTELMAkGA1UEBhMCR0Ix\nEjAQBgNVBAcMCUNhbWJyaWRnZTEYMBYGA1UEAwwPQlRDIFBpbmF0YSBUZWFtMSAw\nHgYJKoZIhvcNAQkBFhFvY2FtbC10bHNAaDNxLmNvbTAeFw0xNTAyMDcxNDUxMjVa\nFw0xNTAzMjkxNDUxMjVaMEwxCzAJBgNVBAYTAkdCMRswGQYDVQQDDBJvd25tZS5p\ncHJlZGF0b3Iuc2UxIDAeBgkqhkiG9w0BCQEWEW9jYW1sLXRsc0BoM3EuY29tMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1o/ufVUoTwZJW+Nc48iuvewy\nDDq2DcVFszilL5XLSIqiFjYhHuZWKTUEmlMTJ+8+1kBNgIQVnyWaWe4J5ps1jXrO\nhHjoG3psxG08sJ8AEoZ2CU7L+CfjrDPzH9dAZVsCJvXEF3n2eNd5fe+OV2vJPW2B\nZkcuZ9jU6t6K64qpAShNDPC5gRcRPQTSY9JnVA35kPTzRmD46nP26MTnswELwSvp\nQUx4e5d0H6WzuOIbLXH5sgR1gAWF062mPLDUpmxwdJkC8tcy7Zk96GXwIwmT2sFr\nf5ZtA0RWJKXXDe4kskKRtfLfQUH2Kyr68Y7PulMrO7ib88IzzFrQ9u3ytBHwlwID\nAQABo10wWzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF4DAdBgNVHQ4EFgQUFvz+\nJzmxEYRkdvUWA8nmmsj+RLYwHwYDVR0jBBgwFoAU9c3PzE6lI0R3Lsys3s8bXz8Z\nyIUwDQYJKoZIhvcNAQEMBQADggIBADwJmfrgNRYzTXJQgqKu6R9iGPd8xX54f8Dd\nGB/QHvTuHXQ2Jw0VMm9RxFAnHqjAbqN4s2LKKzjJIHzRnMTxUtFfkPmuHiOxJX9Z\nWF4SQ/3Zl1YhCGz98POjYQ5de7EQD6ALaNc83GMSo+HJyYPQr0F9ngN2YSV+pSL7\nFRwkdTTUaOEnmAiPqG2IJ7lNxB7zbcDiyO8LTwGFkGlBcH6OJx7FqSpmQRNV72WR\n7xJe0Ekv5Z+IxH5iE7sc1rxZGHQL+vr/CIhdWU4PfENohffAxYKXV7OFjS3In7rc\nlj7y7d+N8Vj+LX+cq76BDNIeQozp4pEzI3ULAoR7AxC/tZ4KOShpyemhR/6dRXmL\nv8/Z/yGQ5KJJjBfdmUpBeBGBOzhidbrcBnmZnRY1x7qrogU10aL9Im5b5CvB1mcb\nfhlip7OlKBYDd4c64XsXKP0KDztrcZZnF8riP9+oJAuJBj/EHr2atZGtkhvXlXhs\nlQBYhftEtUonVCa0SpJ32HcdRfX/bnFdS3VrHZpNyZFjSzXj8ktaJHcft8HIuxhL\no8yfFpO0bksOtrxeJtxw+uQCsDhfIRCRjNA59tVJyDtrn3k8efgtopkBugQmRAMz\ncIk43YKytOooiPQ1zpKI/uh2xkJcFQde913d4ZUC8c0gYRHc1a7D6iADJuNZS54F\nffyV1CXY\n-----END CERTIFICATE-----\n"

let str_to_cs buf =
  let pg = Io_page.to_cstruct (Io_page.get 1) in
  let len = String.length buf in
  Cstruct.blit_from_string buf 0 pg 0 len;
  Cstruct.sub pg 0 len

let () =
  let cs1 = Cstruct.of_string cert
  and cs2 = str_to_cs cert
  in
  assert (Cstruct.len cs1 = Cstruct.len cs2) ;
  let cs3 = Cstruct.create (Cstruct.len cs1) in
  for i = 0 to pred (Cstruct.len cs1) do
    assert (Cstruct.get_uint8 cs1 i = Cstruct.get_uint8 cs2 i) ;
    Cstruct.set_uint8 cs3 i (Cstruct.get_uint8 cs1 i)
  done;
  assert (Nocrypto.Uncommon.Cs.equal ~mask:true cs1 cs3) ;
  assert (Nocrypto.Uncommon.Cs.equal cs1 cs3) ;
  assert (Nocrypto.Uncommon.Cs.equal ~mask:true cs1 cs2) ;
  assert (Nocrypto.Uncommon.Cs.equal cs1 cs2)
