package plugintest

import "github.com/go-dev-auth/go-dev-auth/crypto"

// fastHasher returns scrypt parameters tuned for tests.
//
// Production parameters cost ~50 ms and 32 MiB per hash, which a test
// suite pays on every sign-up and sign-in. Lowering N keeps the same
// code path — salt handling, encoding, constant-time comparison — while
// making the suite run in seconds. Never use these outside tests.
func fastHasher() *crypto.ScryptHasher {
	return crypto.NewScryptHasher(crypto.ScryptParams{
		N: 1024, R: 8, P: 1, KeyLen: 32,
	})
}
