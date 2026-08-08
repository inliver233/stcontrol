package crypto

import (
	"bytes"
	"context"
	"testing"
)

func relayTestContext() RelayCipherContext {
	return RelayCipherContext{
		TaskID:     "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		WorkflowID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		SnapshotID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}
}

func TestRelayCipherRoundTripIsFramedAndSizeBound(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte("stcontrol-relay-data\x00"), 110_000)
	var encrypted bytes.Buffer
	written, err := EncryptRelayStream(context.Background(), &encrypted, bytes.NewReader(plaintext), publicKey, relayTestContext())
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := RelayCiphertextSize(int64(len(plaintext)))
	if err != nil || written != wantSize || int64(encrypted.Len()) != wantSize {
		t.Fatalf("written=%d buffer=%d want=%d err=%v", written, encrypted.Len(), wantSize, err)
	}
	var decrypted bytes.Buffer
	plainBytes, err := DecryptRelayStream(context.Background(), &decrypted, bytes.NewReader(encrypted.Bytes()), privateKey, relayTestContext())
	if err != nil || plainBytes != int64(len(plaintext)) || !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("plainBytes=%d equal=%v err=%v", plainBytes, bytes.Equal(decrypted.Bytes(), plaintext), err)
	}
}

func TestRelayCipherRejectsTamperingWrongContextAndTrailingBytes(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := EncryptRelayStream(
		context.Background(), &encrypted, bytes.NewReader([]byte("secret archive")), publicKey, relayTestContext(),
	); err != nil {
		t.Fatal(err)
	}
	original := encrypted.Bytes()
	for name, ciphertext := range map[string][]byte{
		"tampered": func() []byte { data := append([]byte(nil), original...); data[len(data)/2] ^= 1; return data }(),
		"trailing": append(append([]byte(nil), original...), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := DecryptRelayStream(context.Background(), &out, bytes.NewReader(ciphertext), privateKey, relayTestContext()); err == nil {
				t.Fatalf("%s ciphertext was accepted", name)
			}
		})
	}
	wrongContext := relayTestContext()
	wrongContext.SnapshotID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := DecryptRelayStream(context.Background(), &bytes.Buffer{}, bytes.NewReader(original), privateKey, wrongContext); err == nil {
		t.Fatal("ciphertext was accepted in a different task context")
	}
}

func TestRelayCipherRejectsWrongKeyAndInvalidSizes(t *testing.T) {
	t.Parallel()
	_, publicKey, err := GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPrivate, _, err := GenerateRelayKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := EncryptRelayStream(context.Background(), &encrypted, bytes.NewReader([]byte("secret archive")), publicKey, relayTestContext()); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptRelayStream(context.Background(), &bytes.Buffer{}, bytes.NewReader(encrypted.Bytes()), wrongPrivate, relayTestContext()); err == nil {
		t.Fatal("ciphertext encrypted for a different target key was accepted")
	}
	for _, size := range []int64{0, -1} {
		if _, err := RelayCiphertextSize(size); err == nil {
			t.Fatalf("size %d was accepted", size)
		}
	}
}
