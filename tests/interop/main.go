package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"storj.io/common/base58"
	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/paths"
	"storj.io/common/pb"
	"storj.io/common/storj"
)

const satellite = "satellite.example.test:7777"

var (
	head       = sequence(0)
	secret     = sequence(32)
	defaultKey = mustKey(sequence(64))
	nonce      = []byte{1, 2, 3, 4}
	notBefore  = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	notAfter   = time.Date(2025, 1, 2, 5, 4, 5, 0, time.UTC)
	ttl        = 90 * time.Minute
	prefixes   = []grant.SharePrefix{
		{Bucket: "bucket-alpha", Prefix: "photos/2024"},
		{Bucket: "bucket-beta", Prefix: "docs"},
	}
)

type storeEntry struct {
	bucket, unencrypted, encrypted string
	key                            storj.Key
	cipher                         storj.CipherSuite
}

func main() {
	if len(os.Args) != 2 {
		fatalf("usage: go run . generate|verify")
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate()
	case "verify":
		err = verify()
	default:
		fatalf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func generate() error {
	unrestricted, restricted, err := fixtures()
	if err != nil {
		return err
	}
	u, err := unrestricted.Serialize()
	if err != nil {
		return err
	}
	r, err := restricted.Serialize()
	if err != nil {
		return err
	}
	r, err = canonical(r)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("fixtures", "go.txt"), []byte("unrestricted="+u+"\nrestricted="+r+"\n"), 0644)
}

func verify() error {
	values, err := readFixtures(filepath.Join("fixtures", "python.txt"))
	if err != nil {
		return err
	}
	for _, name := range []string{"unrestricted", "restricted"} {
		if err := verifyAccess(name, values[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func fixtures() (*grant.Access, *grant.Access, error) {
	apiKey, err := macaroon.FromParts(head, secret)
	if err != nil {
		return nil, nil, err
	}
	enc := grant.NewEncryptionAccessWithDefaultKey(&defaultKey)
	enc.SetDefaultPathCipher(storj.EncAESGCM)
	unrestricted := &grant.Access{SatelliteAddress: satellite, APIKey: apiKey, EncAccess: enc}

	caveat := macaroon.Caveat{
		DisallowWrites:                             true,
		DisallowDeletes:                            true,
		DisallowLocks:                              true,
		DisallowGetRetention:                       true,
		DisallowPutLegalHold:                       true,
		DisallowPutBucketObjectLockConfiguration:   true,
		DisallowPutBucketNotificationConfiguration: true,
		NotBefore:                                  &notBefore,
		NotAfter:                                   &notAfter,
		MaxObjectTtl:                               &ttl,
		Nonce:                                      nonce,
	}
	for _, prefix := range prefixes {
		encrypted, err := encryption.EncryptPathWithStoreCipher(prefix.Bucket, paths.NewUnencrypted(prefix.Prefix), enc.Store)
		if err != nil {
			return nil, nil, err
		}
		caveat.AllowedPaths = append(caveat.AllowedPaths, &macaroon.Caveat_Path{
			Bucket: []byte(prefix.Bucket), EncryptedPathPrefix: []byte(encrypted.Raw()),
		})
	}
	restrictedKey, err := apiKey.Restrict(caveat)
	if err != nil {
		return nil, nil, err
	}
	restrictedEnc := enc.Clone()
	restrictedEnc.LimitTo(restrictedKey)
	return unrestricted, &grant.Access{SatelliteAddress: satellite, APIKey: restrictedKey, EncAccess: restrictedEnc}, nil
}

func verifyAccess(name, encoded string) error {
	access, err := grant.ParseAccess(encoded)
	if err != nil {
		return err
	}
	if access.SatelliteAddress != satellite || !bytes.Equal(access.APIKey.Head(), head) {
		return fmt.Errorf("unexpected satellite or API key head")
	}
	if access.EncAccess.Store.GetDefaultPathCipher() != storj.EncAESGCM {
		return fmt.Errorf("unexpected default path cipher")
	}
	mac, err := macaroon.ParseMacaroon(access.APIKey.SerializeRaw())
	if err != nil {
		return err
	}
	entries, err := storeEntries(access)
	if err != nil {
		return err
	}
	serialized, err := access.Serialize()
	if err != nil {
		return err
	}

	if name == "unrestricted" {
		if mac.CaveatLen() != 0 || access.EncAccess.Store.GetDefaultKey() == nil || *access.EncAccess.Store.GetDefaultKey() != defaultKey || len(entries) != 0 {
			return fmt.Errorf("unexpected unrestricted fields")
		}
		if serialized != encoded {
			return fmt.Errorf("unrestricted round trip changed")
		}
		return checkSignature(access, nil)
	}

	if mac.CaveatLen() != 1 || access.EncAccess.Store.GetDefaultKey() != nil {
		return fmt.Errorf("unexpected restricted fields")
	}
	var caveat macaroon.Caveat
	if err := caveat.UnmarshalBinary(mac.Caveats()[0]); err != nil {
		return err
	}
	if err := checkCaveat(&caveat); err != nil {
		return err
	}
	expected, err := expectedEntries()
	if err != nil {
		return err
	}
	if !equalEntries(entries, expected) {
		return fmt.Errorf("unexpected encryption store entries")
	}
	want, err := canonical(encoded)
	if err != nil {
		return err
	}
	got, err := canonical(serialized)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("restricted semantic round trip changed")
	}
	return checkSignature(access, expected)
}

func checkCaveat(c *macaroon.Caveat) error {
	if c.DisallowReads || !c.DisallowWrites || c.DisallowLists || !c.DisallowDeletes ||
		!c.DisallowLocks || c.DisallowPutRetention || !c.DisallowGetRetention ||
		!c.DisallowPutLegalHold || c.DisallowGetLegalHold || c.DisallowBypassGovernanceRetention ||
		!c.DisallowPutBucketObjectLockConfiguration || c.DisallowGetBucketObjectLockConfiguration ||
		!c.DisallowPutBucketNotificationConfiguration || c.DisallowGetBucketNotificationConfiguration ||
		c.NotBefore == nil || !c.NotBefore.Equal(notBefore) || c.NotAfter == nil || !c.NotAfter.Equal(notAfter) ||
		c.MaxObjectTtl == nil || *c.MaxObjectTtl != ttl || !bytes.Equal(c.Nonce, nonce) || len(c.AllowedPaths) != len(prefixes) {
		return fmt.Errorf("unexpected caveat")
	}
	expected, err := expectedEntries()
	if err != nil {
		return err
	}
	for i, path := range c.AllowedPaths {
		if string(path.Bucket) != expected[i].bucket || string(path.EncryptedPathPrefix) != expected[i].encrypted {
			return fmt.Errorf("unexpected allowed path")
		}
	}
	return nil
}

func checkSignature(access *grant.Access, entries []storeEntry) error {
	path := []byte("anything")
	bucket := []byte("anything")
	if len(entries) > 0 {
		bucket, path = []byte(entries[0].bucket), []byte(entries[0].encrypted)
	}
	return access.APIKey.Check(context.Background(), secret,
		macaroon.APIKeyVersionObjectLock|macaroon.APIKeyVersionEventing,
		macaroon.Action{Op: macaroon.ActionRead, Bucket: bucket, EncryptedPath: path, Time: notBefore.Add(time.Minute)}, nil)
}

func expectedEntries() ([]storeEntry, error) {
	unrestricted, _, err := fixtures()
	if err != nil {
		return nil, err
	}
	entries := make([]storeEntry, 0, len(prefixes))
	for _, prefix := range prefixes {
		path := paths.NewUnencrypted(prefix.Prefix)
		encrypted, err := encryption.EncryptPathWithStoreCipher(prefix.Bucket, path, unrestricted.EncAccess.Store)
		if err != nil {
			return nil, err
		}
		key, err := encryption.DerivePathKey(prefix.Bucket, path, unrestricted.EncAccess.Store)
		if err != nil {
			return nil, err
		}
		entries = append(entries, storeEntry{prefix.Bucket, prefix.Prefix, encrypted.Raw(), *key, storj.EncAESGCM})
	}
	sortEntries(entries)
	return entries, nil
}

func storeEntries(access *grant.Access) ([]storeEntry, error) {
	var entries []storeEntry
	err := access.EncAccess.Store.IterateWithCipher(func(bucket string, unencrypted paths.Unencrypted, encrypted paths.Encrypted, key storj.Key, cipher storj.CipherSuite) error {
		entries = append(entries, storeEntry{bucket, unencrypted.Raw(), encrypted.Raw(), key, cipher})
		return nil
	})
	sortEntries(entries)
	return entries, err
}

func sortEntries(entries []storeEntry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		return a.bucket+"\x00"+a.unencrypted+"\x00"+a.encrypted < b.bucket+"\x00"+b.unencrypted+"\x00"+b.encrypted
	})
}

func equalEntries(a, b []storeEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonical(encoded string) (string, error) {
	data, version, err := base58.CheckDecode(encoded)
	if err != nil || version != 0 {
		return "", fmt.Errorf("invalid access grant")
	}
	var scope pb.Scope
	if err := proto.Unmarshal(data, &scope); err != nil {
		return "", err
	}
	if scope.EncryptionAccess != nil {
		sort.Slice(scope.EncryptionAccess.StoreEntries, func(i, j int) bool {
			a, b := scope.EncryptionAccess.StoreEntries[i], scope.EncryptionAccess.StoreEntries[j]
			return bytes.Compare(bytes.Join([][]byte{a.Bucket, a.UnencryptedPath, a.EncryptedPath}, []byte{0}), bytes.Join([][]byte{b.Bucket, b.UnencryptedPath, b.EncryptedPath}, []byte{0})) < 0
		})
	}
	data, err = proto.Marshal(&scope)
	if err != nil {
		return "", err
	}
	return base58.CheckEncode(data, 0), nil
}

func readFixtures(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		return nil, fmt.Errorf("fixture must contain exactly two cases")
	}
	values := make(map[string]string, 2)
	for i, name := range []string{"unrestricted", "restricted"} {
		got, value, ok := strings.Cut(lines[i], "=")
		if !ok || got != name || value == "" {
			return nil, fmt.Errorf("invalid %s fixture", name)
		}
		values[name] = value
	}
	return values, nil
}

func sequence(start byte) []byte {
	value := make([]byte, 32)
	for i := range value {
		value[i] = start + byte(i)
	}
	return value
}

func mustKey(value []byte) storj.Key {
	key, err := storj.NewKey(value)
	if err != nil {
		panic(err)
	}
	return *key
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
