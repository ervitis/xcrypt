package xcrypt

import (
	"testing"
)

type (
	args struct {
		key             []byte
		encryptedText   string
		plaintextString string
	}
	testFeatures struct {
		testName string
		hasError bool
		args     args
		expects  string
	}
)

func TestDecryptCBC(t *testing.T) {
	cases := []testFeatures{
		{
			testName: "decrypt ok",
			hasError: false,
			expects:  "datatoencrypt",
			args:     args{key: []byte("imakeywith16char"), encryptedText: "DDujFSHFCQDrRrow/838WJOzX6iHh0oBPtnKFaX3vck="},
		},
		{
			testName: "decrypt error ciphertext too short",
			hasError: true,
			args:     args{key: []byte("imakeywith16char"), encryptedText: "DDujFSHFCQDaX3vck="},
		},
		{
			testName: "decrypt error new cipher",
			hasError: true,
			args:     args{key: []byte("keywith8"), encryptedText: "DDujFSHFCQDaX3vck="},
		},
		{
			testName: "decrypt cipherText is not a multiple of the block size",
			hasError: true,
			args:     args{key: []byte("imakeywith16char"), encryptedText: "FCQDaX3vck66666666666666="},
		},
	}

	for _, tt := range cases {
		t.Run(tt.testName, func(t *testing.T) {
			s, err := DecryptCBC(tt.args.key, tt.args.encryptedText)
			if tt.hasError && err == nil {
				t.Errorf("%s: error failed when hasError=%v, error=%v", tt.testName, tt.hasError, err)
			}

			if s != tt.expects {
				t.Errorf("%s: expected %s, actual %s", tt.testName, tt.expects, s)
			}
		})
	}
}

func TestEncryptCBC(t *testing.T) {
	cases := []testFeatures{
		{
			testName: "encrypt ok",
			hasError: false,
			args:     args{key: []byte("imakeywith16char"), plaintextString: "datatoencrypt"},
		},
		{
			testName: "encrypt error plaintext is not a multiple of the block size",
			hasError: true,
			args:     args{key: []byte("imakey6char"), plaintextString: "DDujFSHFCQDaX3vck="},
		},
		{
			testName: "encrypt error new cipher",
			hasError: true,
			args:     args{key: []byte("keywith8"), plaintextString: "DDujFSHFCQDaX3vck="},
		},
	}

	for _, tt := range cases {
		t.Run(tt.testName, func(t *testing.T) {
			_, err := EncryptCBC(tt.args.key, tt.args.plaintextString)
			if tt.hasError && err == nil {
				t.Errorf("%s: error failed when hasError=%v, error=%v", tt.testName, tt.hasError, err)
			}
		})
	}
}
