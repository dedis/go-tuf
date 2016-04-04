package signed

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/flynn/go-tuf/Godeps/_workspace/src/github.com/agl/ed25519"
	"github.com/flynn/go-tuf/Godeps/_workspace/src/github.com/tent/canonical-json-go"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
)

var (
	ErrMissingKey    = errors.New("tuf: missing key")
	ErrNoSignatures  = errors.New("tuf: data has no signatures")
	ErrInvalid       = errors.New("tuf: signature verification failed")
	ErrWrongMethod   = errors.New("tuf: invalid signature type")
	ErrUnknownRole   = errors.New("tuf: unknown role")
	ErrRoleThreshold = errors.New("tuf: valid signatures did not meet threshold")
	ErrWrongType     = errors.New("tuf: meta file has wrong type")
)

type signedMeta struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int       `json:"version"`
}

func Verify(s *data.Signed, role string, minVersion int, db *keys.DB) error {
	if err := VerifySignatures(s, role, db); err != nil {
		return err
	}

	sm := &signedMeta{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return err
	}
	if strings.ToLower(sm.Type) != strings.ToLower(role) {
		return ErrWrongType
	}
	if IsExpired(sm.Expires) {
		return ErrExpired{sm.Expires}
	}
	if sm.Version < minVersion {
		return ErrLowVersion{sm.Version, minVersion}
	}

	return nil
}

var IsExpired = func(t time.Time) bool {
	return t.Sub(time.Now()) <= 0
}

func VerifySignatures(s *data.Signed, role string, db *keys.DB) error {
	if len(s.Signatures) == 0 {
		return ErrNoSignatures
	}

	roleData := db.GetRole(role)
	if roleData == nil {
		return ErrUnknownRole
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return err
	}
	msg, err := cjson.Marshal(decoded)
	if err != nil {
		return err
	}

	valid := make(map[string]struct{})
	var sigBytes [ed25519.SignatureSize]byte
	for _, sig := range s.Signatures {
		if _, ok := Verifiers[sig.Method]; !ok {
			return ErrWrongMethod
		}
		if len(sig.Signature) != len(sigBytes) {
			return ErrInvalid
		}

		if !roleData.ValidKey(sig.KeyID) {
			continue
		}
		key := db.GetKey(sig.KeyID)
		if key == nil {
			continue
		}

		copy(sigBytes[:], sig.Signature)
		if err := Verifiers[sig.Method].Verify(key.Public[:], msg, sigBytes[:]); err != nil {
			return err
		}
		valid[sig.KeyID] = struct{}{}
	}
	if len(valid) < roleData.Threshold {
		return ErrRoleThreshold
	}

	return nil
}

func Unmarshal(b []byte, v interface{}, role string, minVersion int, db *keys.DB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := Verify(s, role, minVersion, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}

func UnmarshalTrusted(b []byte, v interface{}, role string, db *keys.DB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := VerifySignatures(s, role, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}

func UnmarshalTrustedTimestamp(b []byte, v interface{}, role string, db *keys.DB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := VerifyTimestampCosi(s); err != nil {
		return err
	}
	if err := VerifySignatures(s, role, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)

}
func UnmarshalTimestamp(b []byte, v interface{}, role string, minVersion int, db *keys.DB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := VerifyTimestamp(s, role, minVersion, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}

func VerifyTimestamp(s *data.Signed, role string, minVersion int, db *keys.DB) error {
	if err := VerifyTimestampCosi(s); err != nil {
		return err
	}
	if err := Verify(s, role, minVersion, db); err != nil {
		return err
	}
	return nil
}

func VerifyTimestampCosi(s *data.Signed) error {
	var cosiSig *data.Signature
	var cosiId int
	for i, s := range s.Signatures {
		if s.KeyID != "cosi" {
			continue
		}
		cosiSig = &s
		cosiId = i
		break
	}
	if cosiSig == nil {
		return errors.New("No CoSi signatures :(")
	}
	// write the sig to a file before
	var cosiFile = "temp.cosi"
	f, err := os.Create(cosiFile + ".sig")
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(cosiFile + ".sig")
	if _, err := f.Write([]byte(cosiSig.Signature)); err != nil {
		return err
	}

	// write the content to a file
	f, err = os.Create(cosiFile)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(cosiFile)
	if _, err := f.Write([]byte(s.Signed)); err != nil {
		return err
	}

	// verify
	cmd := exec.Command("./cosi", "verify", "file", cosiFile)
	var out = new(bytes.Buffer)
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return err
	}
	b, _ := ioutil.ReadAll(out)
	if !bytes.Contains(b, []byte("OK")) {
		return errors.New("Signature invalid?:" + out.String())
	}

	// remove the CoSi signature
	s.Signatures = append(s.Signatures[:cosiId], s.Signatures[cosiId+1:]...)
	return nil
}
