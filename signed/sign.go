package signed

import (
	"github.com/flynn/go-tuf/Godeps/_workspace/src/github.com/agl/ed25519"
	"github.com/flynn/go-tuf/Godeps/_workspace/src/github.com/tent/canonical-json-go"
	"github.com/flynn/go-tuf/data"
	"io/ioutil"
	"os"
	"os/exec"
)

func Sign(s *data.Signed, k *data.Key) {
	id := k.ID()
	signatures := make([]data.Signature, 0, len(s.Signatures)+1)
	for _, sig := range s.Signatures {
		if sig.KeyID == id {
			continue
		}
		signatures = append(signatures, sig)
	}
	priv := [ed25519.PrivateKeySize]byte{}
	copy(priv[:], k.Value.Private)
	sig := ed25519.Sign(&priv, s.Signed)
	s.Signatures = append(signatures, data.Signature{
		KeyID:     id,
		Method:    "ed25519",
		Signature: sig[:],
	})
}

func Marshal(v interface{}, keys ...*data.Key) (*data.Signed, error) {
	b, err := cjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := &data.Signed{Signed: b}
	for _, k := range keys {
		Sign(s, k)
	}
	return s, nil
}

// MarshalTimestamp hijack => sign with CoSi
func MarshalTimestamp(v interface{}, keys ...*data.Key) (*data.Signed, error) {
	s, err := Marshal(v, keys...)
	if err != nil {
		return nil, err
	}

	// write to file
	var sigFile = "temp.cosi"
	f, err := os.Create(sigFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer os.Remove(sigFile)
	if _, err := f.Write([]byte(s.Signed)); err != nil {
		return nil, err
	}
	cmd := exec.Command("./cosi", "sign", "file", sigFile)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	// read the file signature
	f, err = os.Open(sigFile + ".sig")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer os.Remove(sigFile + ".sig")
	var b []byte
	if b, err = ioutil.ReadAll(f); err != nil {
		return nil, err
	}
	sig := data.Signature{
		KeyID:     "cosi",
		Method:    "cosi",
		Signature: b,
	}
	s.Signatures = append(s.Signatures, sig)
	return s, nil
}
