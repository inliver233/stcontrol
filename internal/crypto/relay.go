package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	relayFramePlaintextBytes = 1 << 20
	relayHeaderBytes         = 8 + 32 + 12
	relayFrameHeaderBytes    = 5
	relayFinalFlag           = byte(1)
)

var relayMagic = [8]byte{'S', 'T', 'C', 'R', 'L', 'Y', '1', 0}

type RelayCipherContext struct {
	TaskID     string
	WorkflowID string
	SnapshotID string
}

func GenerateRelayKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate relay X25519 key: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(key.Bytes()),
		base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func RelayCiphertextSize(plaintextBytes int64) (int64, error) {
	if plaintextBytes <= 0 {
		return 0, errors.New("relay plaintext size must be positive")
	}
	frames := (plaintextBytes + relayFramePlaintextBytes - 1) / relayFramePlaintextBytes
	overheadPerFrame := int64(relayFrameHeaderBytes + 16)
	if frames > (math.MaxInt64-int64(relayHeaderBytes)-overheadPerFrame)/overheadPerFrame ||
		plaintextBytes > math.MaxInt64-int64(relayHeaderBytes)-frames*overheadPerFrame-overheadPerFrame {
		return 0, errors.New("relay ciphertext size overflows int64")
	}
	return int64(relayHeaderBytes) + plaintextBytes + frames*overheadPerFrame + overheadPerFrame, nil
}

func EncryptRelayStream(
	ctx context.Context,
	destination io.Writer,
	plaintext io.Reader,
	targetPublicKey string,
	cipherContext RelayCipherContext,
) (int64, error) {
	if destination == nil || plaintext == nil || !validRelayCipherContext(cipherContext) {
		return 0, errors.New("invalid relay encryption input")
	}
	target, err := decodeRelayPublicKey(targetPublicKey)
	if err != nil {
		return 0, err
	}
	sourcePrivate, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		return 0, fmt.Errorf("generate relay source key: %w", err)
	}
	shared, err := sourcePrivate.ECDH(target)
	if err != nil {
		return 0, fmt.Errorf("derive relay shared secret: %w", err)
	}
	aead, contextDigest, err := relayAEAD(shared, cipherContext)
	if err != nil {
		return 0, err
	}
	var baseNonce [12]byte
	if _, err := io.ReadFull(cryptorand.Reader, baseNonce[:]); err != nil {
		return 0, fmt.Errorf("generate relay nonce: %w", err)
	}
	header := make([]byte, 0, relayHeaderBytes)
	header = append(header, relayMagic[:]...)
	header = append(header, sourcePrivate.PublicKey().Bytes()...)
	header = append(header, baseNonce[:]...)
	written, err := writeAll(destination, header)
	if err != nil {
		return int64(written), err
	}
	totalWritten := int64(written)
	buffer := make([]byte, relayFramePlaintextBytes)
	var sequence uint64
	for {
		if err := ctx.Err(); err != nil {
			return totalWritten, err
		}
		count, readErr := io.ReadFull(plaintext, buffer)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return totalWritten, fmt.Errorf("read relay plaintext: %w", readErr)
		}
		if count == 0 {
			break
		}
		frame, err := sealRelayFrame(aead, baseNonce, contextDigest, sequence, buffer[:count], 0)
		if err != nil {
			return totalWritten, err
		}
		countWritten, err := writeAll(destination, frame)
		totalWritten += int64(countWritten)
		if err != nil {
			return totalWritten, err
		}
		sequence++
		if sequence == 0 {
			return totalWritten, errors.New("relay frame sequence exhausted")
		}
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	finalFrame, err := sealRelayFrame(aead, baseNonce, contextDigest, sequence, nil, relayFinalFlag)
	if err != nil {
		return totalWritten, err
	}
	countWritten, err := writeAll(destination, finalFrame)
	totalWritten += int64(countWritten)
	if err != nil {
		return totalWritten, err
	}
	return totalWritten, nil
}

func DecryptRelayStream(
	ctx context.Context,
	destination io.Writer,
	ciphertext io.Reader,
	targetPrivateKey string,
	cipherContext RelayCipherContext,
) (int64, error) {
	if destination == nil || ciphertext == nil || !validRelayCipherContext(cipherContext) {
		return 0, errors.New("invalid relay decryption input")
	}
	target, err := decodeRelayPrivateKey(targetPrivateKey)
	if err != nil {
		return 0, err
	}
	header := make([]byte, relayHeaderBytes)
	if _, err := io.ReadFull(ciphertext, header); err != nil {
		return 0, fmt.Errorf("read relay header: %w", err)
	}
	if string(header[:len(relayMagic)]) != string(relayMagic[:]) {
		return 0, errors.New("invalid relay stream version")
	}
	sourcePublic, err := ecdh.X25519().NewPublicKey(header[8 : 8+32])
	if err != nil {
		return 0, fmt.Errorf("decode relay source key: %w", err)
	}
	shared, err := target.ECDH(sourcePublic)
	if err != nil {
		return 0, fmt.Errorf("derive relay shared secret: %w", err)
	}
	aead, contextDigest, err := relayAEAD(shared, cipherContext)
	if err != nil {
		return 0, err
	}
	var baseNonce [12]byte
	copy(baseNonce[:], header[8+32:])
	var sequence uint64
	var totalPlaintext int64
	for {
		if err := ctx.Err(); err != nil {
			return totalPlaintext, err
		}
		var frameHeader [relayFrameHeaderBytes]byte
		if _, err := io.ReadFull(ciphertext, frameHeader[:]); err != nil {
			return totalPlaintext, fmt.Errorf("read relay frame header: %w", err)
		}
		plaintextLength := binary.BigEndian.Uint32(frameHeader[:4])
		flags := frameHeader[4]
		if plaintextLength > relayFramePlaintextBytes || flags&^relayFinalFlag != 0 ||
			(flags == relayFinalFlag && plaintextLength != 0) || (flags == 0 && plaintextLength == 0) {
			return totalPlaintext, errors.New("invalid relay frame")
		}
		sealed := make([]byte, int(plaintextLength)+aead.Overhead())
		if _, err := io.ReadFull(ciphertext, sealed); err != nil {
			return totalPlaintext, fmt.Errorf("read relay frame: %w", err)
		}
		nonce := relayNonce(baseNonce, sequence)
		aad := relayFrameAAD(contextDigest, sequence, plaintextLength, flags)
		opened, err := aead.Open(nil, nonce[:], sealed, aad)
		if err != nil {
			return totalPlaintext, errors.New("relay frame authentication failed")
		}
		if flags == relayFinalFlag {
			var trailing [1]byte
			if count, err := ciphertext.Read(trailing[:]); count != 0 || (err != nil && err != io.EOF) {
				return totalPlaintext, errors.New("relay stream contains trailing data")
			}
			return totalPlaintext, nil
		}
		count, err := writeAll(destination, opened)
		totalPlaintext += int64(count)
		if err != nil {
			return totalPlaintext, err
		}
		sequence++
		if sequence == 0 {
			return totalPlaintext, errors.New("relay frame sequence exhausted")
		}
	}
}

func decodeRelayPublicKey(encoded string) (*ecdh.PublicKey, error) {
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(data) != 32 {
		return nil, errors.New("invalid relay public key")
	}
	key, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return nil, errors.New("invalid relay public key")
	}
	return key, nil
}

func decodeRelayPrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(data) != 32 {
		return nil, errors.New("invalid relay private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(data)
	if err != nil {
		return nil, errors.New("invalid relay private key")
	}
	return key, nil
}

func relayAEAD(shared []byte, cipherContext RelayCipherContext) (cipher.AEAD, [32]byte, error) {
	contextDigest := sha256.Sum256([]byte(strings.Join([]string{
		"stcontrol-relay-context-v1", cipherContext.TaskID, cipherContext.WorkflowID, cipherContext.SnapshotID,
	}, "\x00")))
	key := make([]byte, 32)
	reader := hkdf.New(sha256.New, shared, contextDigest[:], []byte("stcontrol-relay-aes-256-gcm-v1"))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, [32]byte{}, fmt.Errorf("derive relay encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, [32]byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, contextDigest, err
}

func sealRelayFrame(
	aead cipher.AEAD,
	baseNonce [12]byte,
	contextDigest [32]byte,
	sequence uint64,
	plaintext []byte,
	flags byte,
) ([]byte, error) {
	if len(plaintext) > relayFramePlaintextBytes || flags&^relayFinalFlag != 0 {
		return nil, errors.New("invalid relay frame input")
	}
	frame := make([]byte, relayFrameHeaderBytes, relayFrameHeaderBytes+len(plaintext)+aead.Overhead())
	binary.BigEndian.PutUint32(frame[:4], uint32(len(plaintext)))
	frame[4] = flags
	nonce := relayNonce(baseNonce, sequence)
	aad := relayFrameAAD(contextDigest, sequence, uint32(len(plaintext)), flags)
	return aead.Seal(frame, nonce[:], plaintext, aad), nil
}

func relayNonce(base [12]byte, sequence uint64) [12]byte {
	binary.BigEndian.PutUint64(base[4:], sequence)
	return base
}

func relayFrameAAD(contextDigest [32]byte, sequence uint64, plaintextLength uint32, flags byte) []byte {
	aad := make([]byte, 32+8+4+1)
	copy(aad, contextDigest[:])
	binary.BigEndian.PutUint64(aad[32:40], sequence)
	binary.BigEndian.PutUint32(aad[40:44], plaintextLength)
	aad[44] = flags
	return aad
}

func validRelayCipherContext(value RelayCipherContext) bool {
	return relayContextPart(value.TaskID) && relayContextPart(value.WorkflowID) && relayContextPart(value.SnapshotID)
}

func relayContextPart(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}

func writeAll(destination io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		count, err := destination.Write(data[total:])
		total += count
		if err != nil {
			return total, err
		}
		if count == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
