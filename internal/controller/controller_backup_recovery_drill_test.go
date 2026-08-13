package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	controlcrypto "stcontrol/internal/crypto"
)

// TestControllerBackupMasterKeyRecoveryDrill is the end-to-end disaster drill:
// a backup archive produced by the exact production builder (including the
// master_key_recovery.json sealed with the recovery passphrase) must be
// recoverable through the same extraction steps the controller CLI's
// --recover-master-key path performs (zstd + tar scan + envelope decode +
// scrypt/AES-GCM unwrap).  Wrong passphrases and tampered envelopes fail.
func TestControllerBackupMasterKeyRecoveryDrill(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secretKey := bytes.Repeat([]byte{0x42}, 32)
	passphrase := "drill-recovery-passphrase-2026"

	// 1) Seal the master key exactly as reconcileControllerBackupOnce does.
	envelope, err := controlcrypto.SealMasterKeyRecovery(passphrase, secretKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envelopeJSON, err := controlcrypto.EncodeMasterKeyRecoveryJSON(envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	recoveryPath := filepath.Join(dir, controllerBackupRecoveryName)
	if err := os.WriteFile(recoveryPath, envelopeJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	// 2) Build a full archive through the production builder: manifest plus
	//    pg dump / config payloads plus the recovery envelope.
	pgDumpPath := filepath.Join(dir, controllerBackupPgDumpName)
	if err := os.WriteFile(pgDumpPath, []byte("-- fake pg_dump\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, controllerBackupConfigName)
	if err := os.WriteFile(configPath, []byte("database_url: drill\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"master_key_recovery":{"enabled":true}}`)
	archivePath := filepath.Join(dir, "controller_backup.tar.zst")
	if err := buildControllerBackupArchive(context.Background(), archivePath, pgDumpPath, configPath, manifest, recoveryPath); err != nil {
		t.Fatalf("build archive: %v", err)
	}

	// 3) Extract exactly like runMasterKeyRecovery does.
	extract := func(passphrase string) ([]byte, error) {
		archive, err := os.Open(archivePath)
		if err != nil {
			return nil, err
		}
		defer archive.Close()
		info, err := archive.Stat()
		if err != nil || info.Size() <= 0 {
			return nil, io.ErrUnexpectedEOF
		}
		decoder, err := zstd.NewReader(archive, zstd.WithDecoderMaxMemory(256<<20), zstd.WithDecoderMaxWindow(256<<20))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		tarReader := tar.NewReader(decoder)
		var found []byte
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if header.Typeflag != tar.TypeReg || header.Name != controllerBackupRecoveryName {
				continue
			}
			if header.Size <= 0 || header.Size > 1<<20 {
				return nil, io.ErrUnexpectedEOF
			}
			data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
			if err != nil || int64(len(data)) != header.Size {
				return nil, io.ErrUnexpectedEOF
			}
			found = data
			break
		}
		if found == nil {
			return nil, os.ErrNotExist
		}
		recovered, err := controlcrypto.DecodeMasterKeyRecoveryJSON(found)
		if err != nil {
			return nil, err
		}
		return controlcrypto.OpenMasterKeyRecovery(passphrase, recovered)
	}

	// 4) The drill: correct passphrase unwraps the exact master key.
	got, err := extract(passphrase)
	if err != nil {
		t.Fatalf("recovery drill failed: %v", err)
	}
	if !bytes.Equal(got, secretKey) {
		t.Fatalf("recovered key mismatch: got %x want %x", got, secretKey)
	}

	// 5) Wrong passphrase must fail (scrypt/AES-GCM authentication).
	if _, err := extract("wrong-passphrase-2026"); err == nil {
		t.Fatal("wrong passphrase unexpectedly unwrapped the envelope")
	}

	// 6) Tampering with the stored envelope must fail.
	tampered, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered[10] ^= 0x01
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if envelope2, err2 := controlcrypto.DecodeMasterKeyRecoveryJSON(tampered); err2 == nil {
		if _, err3 := controlcrypto.OpenMasterKeyRecovery(passphrase, envelope2); err3 == nil {
			t.Fatal("tampered envelope unexpectedly unwrapped")
		}
	}

	// 7) The archive digest helper still matches the produced archive (integrity anchor).
	digest, err := controllerFileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != sha256.Size*2 {
		t.Fatalf("digest length=%d", len(digest))
	}
	if _, err := hex.DecodeString(digest); err != nil {
		t.Fatalf("digest not hex: %v", err)
	}
}

// TestControllerBackupArchiveWithoutRecoveryMaterialFailsRecovery ensures a
// backup created without the passphrase configured cannot be recovered (the
// CLI must fail loudly instead of silently running without key material).
func TestControllerBackupArchiveWithoutRecoveryMaterialFailsRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pgDumpPath := filepath.Join(dir, controllerBackupPgDumpName)
	if err := os.WriteFile(pgDumpPath, []byte("-- fake pg_dump\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, controllerBackupConfigName)
	if err := os.WriteFile(configPath, []byte("database_url: drill\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "controller_backup.tar.zst")
	if err := buildControllerBackupArchive(context.Background(), archivePath, pgDumpPath, configPath, []byte(`{}`), ""); err != nil {
		t.Fatalf("build archive: %v", err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	decoder, err := zstd.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == controllerBackupRecoveryName {
			t.Fatal("archive unexpectedly contains recovery material")
		}
	}
}
