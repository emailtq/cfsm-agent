package cfprobe

import (
	"errors"
	"os"
	"path/filepath"
)

func readInstallConfig(paths Paths) (Config, string, error) {
	return readInstallConfigCandidates(paths, legacyConfigFiles(paths))
}

func readInstallConfigCandidates(paths Paths, candidates []string) (Config, string, error) {
	cfg, err := readConfig(paths.ConfigFile)
	if err == nil || errors.Is(err, errLegacyCredential) {
		return cfg, paths.ConfigFile, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return cfg, paths.ConfigFile, err
	}
	for _, path := range candidates {
		if samePath(path, paths.ConfigFile) {
			continue
		}
		cfg, err := readConfig(path)
		if err == nil || errors.Is(err, errLegacyCredential) {
			return cfg, path, err
		}
		if !errors.Is(err, os.ErrNotExist) {
			return Config{}, path, err
		}
	}
	return Config{}, paths.ConfigFile, os.ErrNotExist
}

func migrateTraffic(paths Paths) error {
	if _, err := os.Stat(paths.TrafficFile); err == nil {
		return nil
	}
	for _, oldTrafficFile := range legacyTrafficFiles(paths) {
		if oldTrafficFile == "" || samePath(oldTrafficFile, paths.TrafficFile) {
			continue
		}
		if _, err := os.Stat(oldTrafficFile); err != nil {
			continue
		}
		if err := os.MkdirAll(paths.ConfigDir, 0o755); err != nil {
			return err
		}
		if err := os.Rename(oldTrafficFile, paths.TrafficFile); err != nil {
			return err
		}
		removeDirIfEmpty(filepath.Dir(oldTrafficFile))
		return nil
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o755); err != nil {
		return err
	}
	f, createErr := os.OpenFile(paths.TrafficFile, os.O_CREATE, 0o600)
	if createErr == nil {
		_ = f.Close()
	}
	return createErr
}
