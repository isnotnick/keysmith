# keysmith
Simple Go key-and-CSR generation
--

keysmith is a simple package to generate asymmetric keys (RSA, EC) and then generate PKCS#10 CSR (Certificate Signing Requests) with them.
It also supports the generation of PKCS#12 files from a key and certificate pair.

The idea was to have a simple package in Go that could then be compiled to WASM and used in the browser (Go-compiled-WASM uses WebCrypto so the key generation is done properly) as a KEYGEN tag replacement: https://github.com/isnotnick/keysmith-wasm
