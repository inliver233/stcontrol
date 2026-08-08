package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"stcontrol/internal/config"
)

// ConfigureTavernAdapter enables the opt-in SillyTavern adapter with the
// enrolled node identity. It preserves unrelated YAML nodes and explicitly
// disables the obsolete federated draft so credentials cannot be accepted by
// two protocols at once.
func ConfigureTavernAdapter(cfg *config.AgentConfig) error {
	if cfg == nil || cfg.Role != "compute" || cfg.TavernDir == "" || cfg.NodeID <= 0 ||
		cfg.AgentPSK == "" || cfg.ControllerURL == "" {
		return fmt.Errorf("complete compute enrollment is required")
	}
	configPath := filepath.Join(cfg.TavernDir, "config.yaml")
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SillyTavern config.yaml must be a regular file")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read SillyTavern config: %w", err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("decode SillyTavern config.yaml")
	}
	root := document.Content[0]
	stcontrol := ensureYAMLMapping(root, "stcontrol")
	setYAMLScalar(stcontrol, "enabled", "true", "!!bool")
	setYAMLScalar(stcontrol, "controllerUrl", cfg.ControllerURL, "!!str")
	setYAMLScalar(stcontrol, "nodeId", fmt.Sprintf("%d", cfg.NodeID), "!!int")
	setYAMLScalar(stcontrol, "agentPsk", cfg.AgentPSK, "!!str")
	setYAMLScalar(stcontrol, "controllerGeneration", fmt.Sprintf("%d", cfg.ControllerGeneration), "!!int")
	legacy := ensureYAMLMapping(root, "federated")
	setYAMLScalar(legacy, "enabled", "false", "!!bool")

	encoded, err := yaml.Marshal(&document)
	if err != nil {
		return fmt.Errorf("encode SillyTavern config: %w", err)
	}
	temporary, err := os.CreateTemp(cfg.TavernDir, ".config.yaml.stcontrol-*")
	if err != nil {
		return fmt.Errorf("create SillyTavern config temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	backupPath := configPath + ".pre-stcontrol"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := os.WriteFile(backupPath, data, 0o600); err != nil {
			return fmt.Errorf("backup SillyTavern config: %w", err)
		}
	}
	oldPath := configPath + ".stcontrol-old"
	_ = os.Remove(oldPath)
	if err := os.Rename(configPath, oldPath); err != nil {
		return fmt.Errorf("stage previous SillyTavern config: %w", err)
	}
	if err := os.Rename(temporaryPath, configPath); err != nil {
		_ = os.Rename(oldPath, configPath)
		return fmt.Errorf("publish SillyTavern config: %w", err)
	}
	_ = os.Remove(oldPath)
	return nil
}

func ensureYAMLMapping(parent *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(parent.Content); index += 2 {
		if parent.Content[index].Value == key {
			value := parent.Content[index+1]
			if value.Kind != yaml.MappingNode {
				value.Kind = yaml.MappingNode
				value.Tag = "!!map"
				value.Value = ""
				value.Content = nil
			}
			return value
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, keyNode, valueNode)
	return valueNode
}

func setYAMLScalar(parent *yaml.Node, key, value, tag string) {
	for index := 0; index+1 < len(parent.Content); index += 2 {
		if parent.Content[index].Value == key {
			parent.Content[index+1].Kind = yaml.ScalarNode
			parent.Content[index+1].Tag = tag
			parent.Content[index+1].Value = value
			parent.Content[index+1].Content = nil
			return
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
	)
}
