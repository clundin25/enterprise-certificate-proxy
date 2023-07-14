// Copyright 2022 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin && cgo
// +build darwin,cgo

package keychain

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"unsafe"

	"fmt"
)

func TestKeychainError(t *testing.T) {
	tests := []struct {
		e    keychainError
		want string
	}{
		{e: keychainError(0), want: "No error."},
		{e: keychainError(-4), want: "Function or operation not implemented."},
	}

	for i, test := range tests {
		if got := test.e.Error(); got != test.want {
			t.Errorf("test %d: %#v.Error() = %q, want %q", i, test.e, got, test.want)
		}
	}
}

func TestBytesToCFDataRoundTrip(t *testing.T) {
	want := []byte("an arbitrary and yet coherent byte slice!")
	d := bytesToCFData(want)
	defer cfRelease(unsafe.Pointer(d))
	if got := cfDataToBytes(d); !bytes.Equal(got, want) {
		t.Errorf("bytesToCFData -> cfDataToBytes\ngot  %x\nwant %x", got, want)
	}
}

func TestEncryptRSA(t *testing.T) {
	hashFunc := sha256.New()
	rng := rand.Reader
	key, errCred := Cred("Google Endpoint Verification")
	if errCred != nil {
		t.Errorf("Cred error: %q", errCred)
		return
	}
	publicKey := key.Public()
	message := []byte("Plain text to encrypt")
	label := []byte("test")
	cipherText, errEncrypt := EncryptRSA(hashFunc, rng, publicKey, message, label)
	if errEncrypt != nil {
		t.Errorf("Encrypt error: %q", errEncrypt)
		return
	}
	fmt.Println("Encrypted successfully: ", cipherText)
}

func TestSecKeyEncrypt(t *testing.T) {
	// Getting the public key
	keyPointer, err := Cred("Google Endpoint Verification")
	if err != nil {
		t.Errorf("Cred error: %q", err)
		return
	}
	publicKey := keyPointer.Public()

	// Encrypting
	encryptedData, encryptErr := keyPointer.Encrypt(publicKey)
	if encryptErr != nil {
		t.Errorf("Encrypt error: %q", encryptErr)
		return
	}
	fmt.Println("Encrypted successfully:", encryptedData)
}
