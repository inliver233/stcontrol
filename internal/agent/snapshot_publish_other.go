//go:build !linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

func safeSnapshotStorageError(operation string, _ error) error {
	return fmt.Errorf("%s failed", operation)
}

// Snapshot publication is runtime-disabled outside Linux. These fallbacks keep
// platform-neutral validation tests buildable without claiming crash durability.
func durablySyncSnapshotTree(string) error {
	return nil
}

func recoverSnapshotPublication(string, string) error {
	return nil
}

func syncSnapshotDirectory(string) error {
	return nil
}

func atomicallyReplaceSnapshotDirectory(
	staging, finalPath, taskRoot string,
	checkpoint func(string),
) error {
	previous := filepath.Join(taskRoot, "previous")
	hadPrevious := false
	if _, err := os.Lstat(finalPath); err == nil {
		if err := os.Rename(finalPath, previous); err != nil {
			return err
		}
		hadPrevious = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staging, finalPath); err != nil {
		if hadPrevious {
			_ = os.Rename(previous, finalPath)
		}
		return err
	}
	if checkpoint != nil {
		checkpoint("after_atomic_swap")
		checkpoint("published_durable")
	}
	if hadPrevious {
		removeTaskDirectory(previous)
	}
	return nil
}
