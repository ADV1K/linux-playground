//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

const (
	configFile = "config.json"

	// Constants for ethtool ioctl
	SIOCETHTOOL     = 0x8946
	ETHTOOL_SRXCSUM = 0x15 // Set RX checksumming
	ETHTOOL_STXCSUM = 0x17 // Set TX checksumming
	IFNAMSIZ        = 16
)

// ethtoolValue corresponds to the C struct ethtool_value
type ethtoolValue struct {
	Cmd   uint32
	Value uint32
}

// ifreq corresponds to the C struct ifreq for ioctl calls
type ifreq struct {
	Name [IFNAMSIZ]byte
	Data uintptr
}

// setEthtoolFeature disables a network interface feature (e.g., checksum offloading).
func setEthtoolFeature(ifaceName string, feature uint32, value uint32) error {
	// 1. Create a socket to use for the ioctl call
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("could not create socket: %w", err)
	}
	defer syscall.Close(sock)

	// 2. Create the ethtool and ifreq structs
	eval := ethtoolValue{
		Cmd:   feature,
		Value: value,
	}

	var req ifreq
	copy(req.Name[:], []byte(ifaceName))
	req.Data = uintptr(unsafe.Pointer(&eval))

	// 3. Perform the ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), SIOCETHTOOL, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return fmt.Errorf("ioctl(SIOCETHTOOL) failed: %s", errno)
	}

	return nil
}

func main() {
	log.Println("Starting Go init process...")

	// STEP 1: Load Config
	conf, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}
	confJSON, _ := json.MarshalIndent(conf, "", "  ")
	log.Println("Successfully loaded configuration:", string(confJSON))

	// This helps ensure future child processes don't inherit a restrictive umask.
	syscall.Umask(0)

	// STEP 2: Mount Initial Filesystem
	log.Println("Mounting /dev")
	if err := os.MkdirAll("/dev", 0755); err != nil {
		log.Fatalf("FATAL: Failed to create /dev: %v", err)
	}
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil {
		log.Fatalf("FATAL: Failed to mount devtmpfs on /dev: %v", err)
	}

	log.Println("Mounting new root filesystem")
	if err := os.MkdirAll("/newroot", 0755); err != nil {
		log.Fatalf("FATAL: Failed to create /newroot: %v", err)
	}
	if err := syscall.Mount(conf.RootDevice, "/newroot", "ext4", syscall.MS_RELATIME, ""); err != nil {
		log.Fatalf("FATAL: Failed to mount root device %s on /newroot: %v", conf.RootDevice, err)
	}

	// STEP 3: Switch Root Dance
	log.Println("Moving /dev to the new root filesystem")
	if err := os.MkdirAll("/newroot/dev", 0755); err != nil {
		log.Fatalf("FATAL: Failed to create /newroot/dev: %v", err)
	}
	// syscall.Mount with MS_MOVE atomically moves a mount point.
	if err := syscall.Mount("/dev", "/newroot/dev", "", syscall.MS_MOVE, ""); err != nil {
		log.Fatalf("FATAL: Failed to move /dev to /newroot/dev: %v", err)
	}

	// This directory from the initramfs is no longer needed.
	log.Println("Removing /swim from initramfs")
	if err := os.RemoveAll("/swim"); err != nil {
		// This isn't fatal, but it's good to know if it fails.
		log.Printf("WARN: Could not remove /swim: %v", err)
	}

	log.Println("Pivoting root filesystem")
	// pivot_root requires a place to mount the old root. We create /newroot/oldroot for this.
	oldRoot := "/newroot/oldroot"
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		log.Fatalf("FATAL: Failed to create directory for old root %s: %v", oldRoot, err)
	}

	// We must be inside the new root before calling pivot_root.
	if err := syscall.Chdir("/newroot"); err != nil {
		log.Fatalf("FATAL: Failed to chdir to /newroot: %v", err)
	}

	// syscall.PivotRoot makes the current directory (".") the new root and mounts the old
	// root at "oldroot" (relative to the new root).
	if err := syscall.PivotRoot(".", "oldroot"); err != nil {
		log.Fatalf("FATAL: PivotRoot failed: %v", err)
	}

	// Now that we've pivoted, our working directory is invalid. We must chdir to the new root.
	if err := syscall.Chdir("/"); err != nil {
		log.Fatalf("FATAL: Failed to chdir to new root /: %v", err)
	}

	// The old root is now mounted at /oldroot and is no longer needed.
	// We unmount it lazily (MNT_DETACH) to be safe.
	log.Println("Unmounting and removing old root")
	if err := syscall.Unmount("/oldroot", syscall.MNT_DETACH); err != nil {
		log.Printf("WARN: Failed to unmount old root: %v", err)
	}
	if err := os.RemoveAll("/oldroot"); err != nil {
		log.Printf("WARN: Failed to remove /oldroot directory: %v", err)
	}

	log.Println("Root pivot complete. Now running in the new filesystem.")

	// STEP 3: Mounting Standard Virtual Filesystems

	log.Println("Mounting standard virtual filesystems")

	// --- /dev/pts ---
	if err := os.MkdirAll("/dev/pts", 0755); err != nil {
		log.Fatalf("FATAL: Failed to create /dev/pts: %v", err)
	}
	if err := syscall.Mount("devpts", "/dev/pts", "devpts", syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NOATIME, "gid=5,mode=620,ptmxmode=666"); err != nil {
		log.Fatalf("FATAL: Failed to mount /dev/pts: %v", err)
	}

	// --- /dev/shm ---
	if err := os.MkdirAll("/dev/shm", 01777); err != nil {
		log.Fatalf("FATAL: Failed to create /dev/shm: %v", err)
	}
	if err := syscall.Mount("shm", "/dev/shm", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, ""); err != nil {
		log.Fatalf("FATAL: Failed to mount /dev/shm: %v", err)
	}

	// --- /proc ---
	if err := os.MkdirAll("/proc", 0555); err != nil {
		log.Fatalf("FATAL: Failed to create /proc: %v", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, ""); err != nil {
		log.Fatalf("FATAL: Failed to mount /proc: %v", err)
	}

	// --- /sys ---
	if err := os.MkdirAll("/sys", 0555); err != nil {
		log.Fatalf("FATAL: Failed to create /sys: %v", err)
	}
	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, ""); err != nil {
		log.Fatalf("FATAL: Failed to mount /sys: %v", err)
	}

	// --- /run ---
	if err := os.MkdirAll("/run", 0755); err != nil {
		log.Fatalf("FATAL: Failed to create /run: %v", err)
	}
	if err := syscall.Mount("run", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755"); err != nil {
		log.Fatalf("FATAL: Failed to mount /run: %v", err)
	}

	// --- Create standard symlinks ---
	log.Println("Creating standard symlinks in /dev")
	if err := os.Symlink("/proc/self/fd", "/dev/fd"); err != nil {
		log.Printf("WARN: Failed to create symlink /dev/fd: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/0", "/dev/stdin"); err != nil {
		log.Printf("WARN: Failed to create symlink /dev/stdin: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/1", "/dev/stdout"); err != nil {
		log.Printf("WARN: Failed to create symlink /dev/stdout: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/2", "/dev/stderr"); err != nil {
		log.Printf("WARN: Failed to create symlink /dev/stderr: %v", err)
	}

	log.Println("Mounting cgroup filesystems")

	// First, mount a tmpfs as the root for all cgroup mounts.
	cgroupRoot := "/sys/fs/cgroup"
	if err := os.MkdirAll(cgroupRoot, 0755); err != nil {
		log.Fatalf("FATAL: Failed to create %s: %v", cgroupRoot, err)
	}
	if err := syscall.Mount("tmpfs", cgroupRoot, "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "mode=0755"); err != nil {
		log.Fatalf("FATAL: Failed to mount tmpfs on %s: %v", cgroupRoot, err)
	}

	// Define common flags for most cgroup mounts.
	commonCgroupMountFlags := uintptr(syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_RELATIME)

	// --- Mount cgroup2 (unified hierarchy) ---
	cgroup2Path := "/sys/fs/cgroup/unified"
	log.Printf("Mounting cgroup2 at %s", cgroup2Path)
	if err := os.MkdirAll(cgroup2Path, 0555); err != nil {
		log.Fatalf("FATAL: Failed to create %s: %v", cgroup2Path, err)
	}
	if err := syscall.Mount("cgroup2", cgroup2Path, "cgroup2", commonCgroupMountFlags, "nsdelegate"); err != nil {
		log.Fatalf("FATAL: Failed to mount cgroup2 at %s: %v", cgroup2Path, err)
	}

	// --- Mount cgroup v1 controllers ---
	// Define all the v1 controllers we need to mount.
	cgroupV1Controllers := []string{
		"net_cls,net_prio",
		"hugetlb",
		"pids",
		"freezer",
		"cpu,cpuacct",
		"devices",
		"blkio",
		"memory",
		"perf_event",
		"cpuset",
	}

	for _, controller := range cgroupV1Controllers {
		path := "/sys/fs/cgroup/" + controller
		log.Printf("Mounting cgroup v1 controller at %s", path)

		if err := os.MkdirAll(path, 0555); err != nil {
			log.Fatalf("FATAL: Failed to create %s: %v", path, err)
		}
		if err := syscall.Mount("cgroup", path, "cgroup", commonCgroupMountFlags, controller); err != nil {
			log.Fatalf("FATAL: Failed to mount cgroup controller %s: %v", controller, err)
		}
	}

	// STEP 4: System and App Configuration

	log.Println("Applying system configurations")

	// --- Set resource limits ---
	// The reference code sets a NOFILE limit of 10240.
	var rlimit syscall.Rlimit
	rlimit.Cur = 10240
	rlimit.Max = 10240
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		log.Printf("WARN: Failed to set NOFILE rlimit: %v", err)
	}

	// --- User and Group Resolution ---
	log.Println("Resolving user and group")
	var uid, gid int
	var homeDir string

	// Determine the target user string (user:group) from the config hierarchy.
	userStr := "root" // Default user
	if conf.ImageConfig != nil && conf.ImageConfig.User != "" {
		userStr = conf.ImageConfig.User
	}
	if conf.UserOverride != "" {
		userStr = conf.UserOverride
	}

	// The user string can be in the format "user:group" or just "user".
	parts := strings.SplitN(userStr, ":", 2)
	userName := parts[0]
	groupName := ""
	if len(parts) > 1 {
		groupName = parts[1]
	}

	// Look up the user by name or by UID string.
	u, err := user.Lookup(userName)
	if err != nil {
		// If lookup fails, maybe it's a numeric UID.
		uid, err = strconv.Atoi(userName)
		if err != nil {
			log.Fatalf("FATAL: Cannot find user '%s' and it's not a valid UID: %v", userName, err)
		}
		// If it's a numeric UID, we assume the GID is the same, and home is "/".
		gid = uid
		homeDir = "/"
	} else {
		uid, _ = strconv.Atoi(u.Uid)
		homeDir = u.HomeDir
		// If no group was specified, use the user's primary group.
		if groupName == "" {
			gid, _ = strconv.Atoi(u.Gid)
		}
	}

	// If a group was explicitly specified, look it up.
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			// If lookup fails, maybe it's a numeric GID.
			gid, err = strconv.Atoi(groupName)
			if err != nil {
				log.Fatalf("FATAL: Cannot find group '%s' and it's not a valid GID: %v", groupName, err)
			}
		} else {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	log.Printf("Resolved user to uid=%d, gid=%d, home=%s", uid, gid, homeDir)

	// --- Set Hostname ---
	if conf.Hostname != "" {
		log.Printf("Setting hostname to %s", conf.Hostname)
		if err := syscall.Sethostname([]byte(conf.Hostname)); err != nil {
			log.Printf("WARN: Failed to set hostname: %v", err)
		}
		// Also write to /etc/hostname for compatibility.
		if err := os.MkdirAll("/etc", 0755); err != nil {
			log.Printf("WARN: Failed to create /etc directory: %v", err)
		}
		if err := os.WriteFile("/etc/hostname", []byte(conf.Hostname), 0644); err != nil {
			log.Printf("WARN: Failed to write to /etc/hostname: %v", err)
		}
	}

	// --- Write /etc/hosts ---
	if len(conf.EtcHosts) > 0 {
		log.Println("Populating /etc/hosts")
		var hostsContent strings.Builder
		// Always good to have localhost.
		hostsContent.WriteString("127.0.0.1\tlocalhost\n")
		hostsContent.WriteString("::1\t\tlocalhost\n")

		for _, entry := range conf.EtcHosts {
			if entry.Desc != nil {
				hostsContent.WriteString(fmt.Sprintf("\n# %s\n", *entry.Desc))
			}
			hostsContent.WriteString(fmt.Sprintf("%s\t%s\n", entry.IP, entry.Host))
		}
		if err := os.WriteFile("/etc/hosts", []byte(hostsContent.String()), 0644); err != nil {
			log.Printf("WARN: Failed to write /etc/hosts: %v", err)
		}
	}

	// --- Write /etc/resolv.conf ---
	if conf.EtcResolv != nil && len(conf.EtcResolv.Nameservers) > 0 {
		log.Println("Populating /etc/resolv.conf")
		var resolvContent strings.Builder
		for _, ns := range conf.EtcResolv.Nameservers {
			resolvContent.WriteString(fmt.Sprintf("nameserver %s\n", ns))
		}
		if err := os.WriteFile("/etc/resolv.conf", []byte(resolvContent.String()), 0644); err != nil {
			log.Printf("WARN: Failed to write /etc/resolv.conf: %v", err)
		}
	}

	// --- Handle additional mounts ---
	if len(conf.Mounts) > 0 {
		log.Println("Processing additional volume mounts")
		for _, m := range conf.Mounts {
			log.Printf("Mounting %s at %s", m.DevicePath, m.MountPath)
			if err := os.MkdirAll(m.MountPath, 0755); err != nil {
				// Don't fail if the directory already exists
				if !os.IsExist(err) {
					log.Fatalf("FATAL: Could not create mount directory %s: %v", m.MountPath, err)
				}
			}
			if err := syscall.Mount(m.DevicePath, m.MountPath, "ext4", syscall.MS_RELATIME, ""); err != nil {
				log.Fatalf("FATAL: Failed to mount %s at %s: %v", m.DevicePath, m.MountPath, err)
			}
			// Chown the mount point to the target user.
			if err := os.Chown(m.MountPath, uid, gid); err != nil {
				log.Printf("WARN: Failed to chown %s to %d:%d: %v", m.MountPath, uid, gid, err)
			}
		}
	}

	log.Println("Configuring network interfaces")

	// --- Bring 'lo' interface up ---
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		log.Fatalf("FATAL: Could not find 'lo' interface: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		log.Fatalf("FATAL: Failed to bring up 'lo' interface: %v", err)
	}

	// --- Configure 'eth0' interface ---
	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		log.Fatalf("FATAL: Could not find 'eth0' interface: %v", err)
	}

	// Set MTU and bring the interface up
	// if err := netlink.LinkSetMTU(eth0, 1420); err != nil {
	// 	log.Printf("WARN: Failed to set MTU on eth0: %v", err)
	// }
	// if err := netlink.LinkSetUp(eth0); err != nil {
	// 	log.Fatalf("FATAL: Failed to bring up 'eth0' interface: %v", err)
	// }

	// Disable checksum offloading
	log.Println("Disabling TCP checksum offloading on eth0")
	if err := setEthtoolFeature("eth0", ETHTOOL_STXCSUM, 0); err != nil {
		log.Printf("WARN: Failed to disable TX checksum offload on eth0: %v", err)
	}
	if err := setEthtoolFeature("eth0", ETHTOOL_SRXCSUM, 0); err != nil {
		log.Printf("WARN: Failed to disable RX checksum offload on eth0: %v", err)
	}

	// --- Add IP addresses and routes ---
	if len(conf.IPConfigs) > 0 {
		log.Println("Assigning IP addresses and routes")
		for _, ipc := range conf.IPConfigs {
			addrStr := fmt.Sprintf("%s/%s", ipc.IP.String(), strconv.Itoa(ipc.Mask))
			addr, err := netlink.ParseAddr(addrStr)
			addr.Flags = syscall.IFA_F_NODAD // Disable Duplicate Address Detection
			if err != nil {
				log.Fatalf("FATAL: Failed to parse IP address %s: %v", addrStr, err)
			}

			if err := netlink.AddrAdd(eth0, addr); err != nil {
				log.Fatalf("FATAL: Failed to add IP %s to eth0: %v", addrStr, err)
			}
			log.Printf("Added IP %s to eth0", addrStr)

			if ipc.Gateway != nil {
				route := &netlink.Route{
					Gw: ipc.Gateway,
				}
				if err := netlink.RouteAdd(route); err != nil {
					log.Fatalf("FATAL: Failed to add default route via %s: %v", ipc.Gateway, err)
				}
				log.Printf("Added default route via %s", ipc.Gateway)
			}
		}
	}
}
