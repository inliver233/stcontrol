//go:build linux

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func safeSnapshotStorageError(operation string, err error) error {
	if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) {
		return fmt.Errorf("%s: %w", operation, errSnapshotStorageExhausted)
	}
	return fmt.Errorf("%s failed", operation)
}

// durablySyncSnapshotTree persists file contents and every directory entry
// before the staging tree can become the visible replica.
func durablySyncSnapshotTree(root string) error {
	directories := make([]string, 0, 8)
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("read snapshot staging entry failed")
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported snapshot staging entry")
		}
		if info.IsDir() {
			directories = append(directories, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return safeSnapshotStorageError("open snapshot staging file", err)
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return safeSnapshotStorageError("sync snapshot staging file", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close snapshot staging file failed")
		}
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncSnapshotDirectory(directories[index]); err != nil {
			return safeSnapshotStorageError("sync snapshot staging directory", err)
		}
	}
	return nil
}

func atomicallyReplaceSnapshotDirectory(
	staging, finalPath, taskRoot string,
	checkpoint func(string),
) error {
	return atomicallyReplaceSnapshotDirectoryWithExchange(
		staging, finalPath, taskRoot, checkpoint,
		func(oldPath, newPath string) error {
			return unix.Renameat2(
				unix.AT_FDCWD, oldPath,
				unix.AT_FDCWD, newPath,
				unix.RENAME_EXCHANGE,
			)
		},
	)
}

func atomicallyReplaceSnapshotDirectoryWithExchange(
	staging, finalPath, taskRoot string,
	checkpoint func(string),
	exchange func(string, string) error,
) error {
	hadPrevious := false
	if _, err := os.Lstat(finalPath); err == nil {
		if err := exchange(staging, finalPath); err != nil {
			// Never degrade to a two-rename replacement: that would expose a
			// missing/partial replica. Filesystems without RENAME_EXCHANGE are
			// unsuitable for replacing an existing published snapshot.
			return fmt.Errorf("atomic snapshot exchange unavailable: %w", err)
		}
		hadPrevious = true
	} else if os.IsNotExist(err) {
		if err := os.Rename(staging, finalPath); err != nil {
			return safeSnapshotStorageError("atomically publish snapshot replica", err)
		}
	} else {
		return fmt.Errorf("inspect snapshot destination failed")
	}
	if checkpoint != nil {
		checkpoint("after_atomic_swap")
	}
	if err := syncSnapshotDirectory(filepath.Dir(finalPath)); err != nil {
		return safeSnapshotStorageError("sync snapshot publication parent", err)
	}
	if hadPrevious {
		if err := syncSnapshotDirectory(taskRoot); err != nil {
			return safeSnapshotStorageError("sync snapshot exchange parent", err)
		}
	}
	if checkpoint != nil {
		checkpoint("published_durable")
	}
	if hadPrevious {
		removeTaskDirectory(staging)
		if err := syncSnapshotDirectory(taskRoot); err != nil {
			return safeSnapshotStorageError("sync previous snapshot cleanup", err)
		}
	}
	return nil
}

func recoverSnapshotPublication(string, string) error {
	// RENAME_EXCHANGE is a single namespace transaction: after a crash the
	// visible name is either the complete old tree or the complete new tree.
	return nil
}

func syncSnapshotDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
