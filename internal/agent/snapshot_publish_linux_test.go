//go:build linux

package agent

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/protocol"
)

const snapshotPublishCrashHelperEnv = "STCONTROL_SNAPSHOT_PUBLISH_CRASH_HELPER"

func TestSnapshotPublishCrashHelper(t *testing.T) {
	if os.Getenv(snapshotPublishCrashHelperEnv) != "1" {
		t.Skip("snapshot publish crash helper")
	}
	checkpoint := os.Getenv("STCONTROL_SNAPSHOT_PUBLISH_CHECKPOINT")
	marker := os.Getenv("STCONTROL_SNAPSHOT_PUBLISH_MARKER")
	staging := os.Getenv("STCONTROL_SNAPSHOT_PUBLISH_STAGING")
	finalPath := os.Getenv("STCONTROL_SNAPSHOT_PUBLISH_FINAL")
	taskRoot := os.Getenv("STCONTROL_SNAPSHOT_PUBLISH_TASK")
	hook := func(current string) {
		if current != checkpoint {
			return
		}
		file, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			panic(err)
		}
		if _, err := file.WriteString(current); err != nil {
			panic(err)
		}
		if err := file.Sync(); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
		select {}
	}
	err := publishSnapshotDirectoryWithCheckpoint(staging, finalPath, taskRoot, hook)
	if err != nil {
		t.Fatalf("publish before checkpoint %s: %v", checkpoint, err)
	}
	t.Fatalf("publish returned before checkpoint %s", checkpoint)
}

func TestSnapshotPublishSurvivesCrashAtEveryAtomicBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("filesystem crash injection is disabled in short mode")
	}
	for _, checkpoint := range []string{"staging_durable", "after_atomic_swap", "published_durable"} {
		checkpoint := checkpoint
		t.Run(checkpoint, func(t *testing.T) {
			root := t.TempDir()
			taskRoot := filepath.Join(root, ".stcontrol-tasks", testWorkflowID, testSnapshotID)
			staging := filepath.Join(taskRoot, "staging")
			finalPath := filepath.Join(root, "replicas", "alice")
			for _, directory := range []string{staging, finalPath} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(staging, "new.txt"), []byte("new-replica"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("old-replica"), 0o600); err != nil {
				t.Fatal(err)
			}
			output := crashSnapshotPublisherAt(t, staging, finalPath, taskRoot, checkpoint)

			wantName := "new.txt"
			wantContent := "new-replica"
			if checkpoint == "staging_durable" {
				wantName = "old.txt"
				wantContent = "old-replica"
			}
			got, err := os.ReadFile(filepath.Join(finalPath, wantName))
			if err != nil || string(got) != wantContent {
				t.Fatalf("visible replica at %s=%q err=%v; helper=%s", checkpoint, got, err, output)
			}
			if err := resetSnapshotTaskDirectory(taskRoot, finalPath); err != nil {
				t.Fatalf("restart cleanup: %v", err)
			}
			got, err = os.ReadFile(filepath.Join(finalPath, wantName))
			if err != nil || string(got) != wantContent {
				t.Fatalf("restart changed visible replica at %s: %q err=%v", checkpoint, got, err)
			}
			removeTaskDirectory(taskRoot)
		})
	}
}

func crashSnapshotPublisherAt(t *testing.T, staging, finalPath, taskRoot, checkpoint string) string {
	t.Helper()
	marker := filepath.Join(filepath.Dir(taskRoot), "checkpoint-"+checkpoint)
	command := exec.Command(os.Args[0], "-test.run=^TestSnapshotPublishCrashHelper$", "-test.v")
	command.Env = append(os.Environ(),
		snapshotPublishCrashHelperEnv+"=1",
		"STCONTROL_SNAPSHOT_PUBLISH_CHECKPOINT="+checkpoint,
		"STCONTROL_SNAPSHOT_PUBLISH_MARKER="+marker,
		"STCONTROL_SNAPSHOT_PUBLISH_STAGING="+staging,
		"STCONTROL_SNAPSHOT_PUBLISH_FINAL="+finalPath,
		"STCONTROL_SNAPSHOT_PUBLISH_TASK="+taskRoot,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("helper did not reach %s: %s", checkpoint, output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	return output.String()
}

func TestAgentRestartCleansAtomicSwapBeforeRearmingConsumedCapability(t *testing.T) {
	root := t.TempDir()
	cfg := &config.AgentConfig{
		Role: "storage", NodeID: 9, AgentPSK: "restart-recovery-psk",
		ControllerURL: "http://127.0.0.1:1", DataDir: filepath.Join(root, "runtime"),
		BackupDir: filepath.Join(root, "backups"), ControllerGeneration: 1,
	}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token := "restart-recovery-one-use-capability"
	tokenHash := sha256.Sum256([]byte(token))
	transfer := pendingTransfer{
		WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
		TargetNodeID: 9, Handle: "alice", DestinationKind: "archive",
		SourceNodeID: 8, ActivityEpoch: 4, CapabilityHash: hex.EncodeToString(tokenHash[:]),
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if err := first.prepareTransfer(transfer); err != nil {
		t.Fatal(err)
	}
	consumed, err := first.consumeTransfer(testSnapshotID, testWorkflowID, token, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	taskRoot, finalPath, err := first.targetSnapshotPaths(consumed)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(taskRoot, "staging")
	for _, directory := range []string{staging, finalPath} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "new.txt"), []byte("new-replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("old-replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	crashSnapshotPublisherAt(t, staging, finalPath, taskRoot, "after_atomic_swap")
	restarted, err := New(cfg)
	if err != nil {
		t.Fatalf("restart Agent: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(finalPath, "new.txt"))
	if err != nil || string(got) != "new-replica" {
		t.Fatalf("restart did not keep the complete swapped replica: %q err=%v", got, err)
	}
	if _, err := os.Stat(taskRoot); !os.IsNotExist(err) {
		t.Fatalf("restart left publication task debris: %v", err)
	}
	restarted.stateMu.Lock()
	rearmed := restarted.state.Transfers[testSnapshotID]
	restarted.stateMu.Unlock()
	if rearmed.State != "prepared" || rearmed.CapabilityHash != transfer.CapabilityHash {
		t.Fatalf("restart transfer state=%+v", rearmed)
	}
}

func TestSnapshotFileWritePropagatesKernelDiskFull(t *testing.T) {
	device, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("kernel disk-full device unavailable: %v", err)
	}
	defer device.Close()
	content := bytes.Repeat([]byte("disk-pressure"), 1024)
	digest := sha256.Sum256(content)
	err = copyVerifiedSnapshotFile(device, bytes.NewReader(content), protocol.ManifestEntry{
		Path: "settings.json", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
	})
	if !errors.Is(err, errSnapshotStorageExhausted) {
		t.Fatalf("disk-full error=%v, want bounded storage-exhausted reason", err)
	}
	if strings.Contains(err.Error(), "/dev/full") {
		t.Fatalf("disk-full reason leaked a local path: %v", err)
	}
}

func TestSnapshotUnsupportedAtomicExchangeKeepsPreviousReplica(t *testing.T) {
	root := t.TempDir()
	taskRoot := filepath.Join(root, ".stcontrol-tasks", testWorkflowID, testSnapshotID)
	staging := filepath.Join(taskRoot, "staging")
	finalPath := filepath.Join(root, "replicas", "alice")
	for _, directory := range []string{staging, finalPath} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "new.txt"), []byte("new-replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("old-replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := atomicallyReplaceSnapshotDirectoryWithExchange(
		staging, finalPath, taskRoot, nil,
		func(string, string) error { return errors.New("exchange unsupported") },
	)
	if err == nil {
		t.Fatal("unsupported atomic exchange degraded to a non-atomic replacement")
	}
	oldData, oldErr := os.ReadFile(filepath.Join(finalPath, "old.txt"))
	newData, newErr := os.ReadFile(filepath.Join(staging, "new.txt"))
	if oldErr != nil || string(oldData) != "old-replica" || newErr != nil || string(newData) != "new-replica" {
		t.Fatalf("exchange failure changed trees: old=%q/%v new=%q/%v", oldData, oldErr, newData, newErr)
	}
}

func TestSnapshotPublishesLargeArchiveWithoutPartialReplica(t *testing.T) {
	if testing.Short() {
		t.Skip("large archive filesystem test is disabled in short mode")
	}
	const contentSize = int64(32 << 20)
	root := t.TempDir()
	sourceRoot := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceRoot, "large.bin")
	source, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(source, hash), cryptorand.Reader, contentSize)
	syncErr := source.Sync()
	closeErr := source.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != contentSize {
		t.Fatalf("create large source: written=%d copy=%v sync=%v close=%v", written, copyErr, syncErr, closeErr)
	}
	manifest := protocol.SnapshotManifest{
		FormatVersion: 1, WorkflowID: testWorkflowID, SnapshotID: testSnapshotID,
		GlobalUserID: 70, Handle: "alice", SourceNodeID: 8, TargetNodeID: 9,
		ActivityEpoch: 4, CreatedAt: time.Now().UTC(),
		Files: []protocol.ManifestEntry{{
			Path: "large.bin", Size: contentSize, SHA256: hex.EncodeToString(hash.Sum(nil)),
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "large.tar.zst")
	if err := createSnapshotArchive(context.Background(), archivePath, sourceRoot, manifestJSON, manifest.Files); err != nil {
		t.Fatal(err)
	}
	archiveDigest, err := hashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	taskRoot := filepath.Join(root, ".stcontrol-tasks", testWorkflowID, testSnapshotID)
	if err := os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(root, "replicas", "alice")
	if err := os.MkdirAll(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(finalPath, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := extractVerifyAndPublish(
		context.Background(), archivePath, taskRoot, finalPath,
		pendingTransfer{
			WorkflowID: testWorkflowID, SnapshotID: testSnapshotID, GlobalUserID: 70,
			TargetNodeID: 9, Handle: "alice", DestinationKind: "archive",
			SourceNodeID: 8, ActivityEpoch: 4,
		}, archiveDigest[:], func() error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TotalBytes != contentSize || receipt.FileCount != 1 {
		t.Fatalf("large archive receipt=%+v", receipt)
	}
	publishedDigest, err := hashFile(filepath.Join(finalPath, "large.bin"))
	if err != nil || hex.EncodeToString(publishedDigest[:]) != manifest.Files[0].SHA256 {
		t.Fatalf("large published digest=%x err=%v", publishedDigest, err)
	}
	if _, err := os.Stat(filepath.Join(finalPath, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("partial old replica survived large publication: %v", err)
	}
}
