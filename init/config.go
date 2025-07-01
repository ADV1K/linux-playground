package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
)

const defaultRootDevice = "/dev/vdb"

// RunConfig holds the entire configuration for the VM initialization.
type RunConfig struct {
	Hostname     string            `json:"hostname"`
	RootDevice   string            `json:"root_device"`
	TTY          bool              `json:"tty"`
	ImageConfig  *ImageConfig      `json:"image_config"`
	IPConfigs    []IPConfig        `json:"ip_configs"`
	Mounts       []Mount           `json:"mounts"`
	EtcHosts     []EtcHost         `json:"etc_hosts"`
	EtcResolv    *EtcResolv        `json:"etc_resolv"`
	ExecOverride string            `json:"exec_override"`
	UserOverride string            `json:"user_override"`
	CmdOverride  string            `json:"cmd_override"`
	ExtraEnv     map[string]string `json:"extra_env"`
}

// ImageConfig contains details from the container image configuration.
type ImageConfig struct {
	Entrypoint []string `json:"entrypoint"`
	Cmd        []string `json:"cmd"`
	Env        []string `json:"env"`
	WorkingDir string   `json:"working_dir"`
	User       string   `json:"user"`
}

// IPConfig defines the network configuration for an interface.
type IPConfig struct {
	Gateway net.IP `json:"gateway"`
	IP      net.IP `json:"ip"`
	Mask    int    `json:"mask"`
}

// Mount defines a filesystem to be mounted.
type Mount struct {
	MountPath  string `json:"mount_path"`
	DevicePath string `json:"device_path"`
}

// EtcHost represents a single entry in /etc/hosts.
type EtcHost struct {
	Host string  `json:"host"`
	IP   string  `json:"ip"`
	Desc *string `json:"desc"`
}

// EtcResolv represents the configuration for /etc/resolv.conf.
type EtcResolv struct {
	Nameservers []string `json:"nameservers"`
}

// loadConfig reads and parses the JSON configuration file.
func loadConfig(path string) (*RunConfig, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config RunConfig
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, err
	}

	if config.RootDevice == "" {
		log.Printf("Root device not specified, defaulting to %s", defaultRootDevice)
		config.RootDevice = defaultRootDevice
	}

	return &config, nil
}
