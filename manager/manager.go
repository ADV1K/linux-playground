package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/adv1k/linux-playground/init/pb"
	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	firecracker_models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const firecrackerBin = "firecracker"
const defaultKernelImage = "images/vmlinux-6.12"
const defaultKernelArgs = "noapic reboot=k panic=1 pci=off nomodules random.trust_cpu=on"
const defaultSystemImage = "images/ubuntu.img"
const defaultMemory = 256
const defaultCpuCount = 2
const defaultBridge = "br0"
const defaultVmInterface = "eth0"

var defaultIP = net.IPNet{
	IP:   net.IPv4(192, 168, 1, 201),
	Mask: net.IPv4Mask(255, 255, 255, 0),
}
var defaultGateway = net.IPv4(192, 168, 1, 1)
var defaultNameservers = []string{
	"1.1.1.1",
	"1.0.0.1",
}
var DefaultOpts VmOptions = VmOptions{
	CPUCount:        defaultCpuCount,
	Memory:          defaultMemory,
	IPv4:            defaultIP,
	Gateway:         defaultGateway,
	Nameservers:     defaultNameservers,
	FirecrackerBin:  firecrackerBin,
	SystemImagePath: defaultSystemImage,
	KernelImagePath: defaultKernelImage,
	KernelArgs:      defaultKernelArgs,
}

type VmOptions struct {
	CPUCount        int64
	Memory          int64
	IPv4            net.IPNet
	Gateway         net.IP
	Nameservers     []string
	FirecrackerBin  string
	SystemImagePath string
	KernelImagePath string
	KernelArgs      string
}

type VM struct {
	ID      uuid.UUID
	Ctx     context.Context
	IPv6    string
	Stdin   *bytes.Buffer
	Stdout  *bytes.Buffer
	Stderr  *bytes.Buffer
	Machine *firecracker.Machine
	ShortID string
}

func NewVM(opts VmOptions) VM {
	id := uuid.New()
	shortID := strings.Split(id.String(), "-")[0]

	config := firecracker.Config{
		// LogLevel:        "Debug",
		// LogPath:         "log.txt",
		VMID:            id.String(),
		SocketPath:      fmt.Sprintf("/tmp/%s.socket", shortID),
		KernelImagePath: opts.KernelImagePath,
		KernelArgs:      fmt.Sprintf("console=ttyS0 %s", opts.KernelArgs),
		Drives: []firecracker_models.Drive{
			firecracker_models.Drive{
				DriveID:      firecracker.String("rootfs"),
				PathOnHost:   firecracker.String(opts.SystemImagePath),
				IsRootDevice: firecracker.Bool(true),
				IsReadOnly:   firecracker.Bool(false),
			},
		},
		NetworkInterfaces: []firecracker.NetworkInterface{
			firecracker.NetworkInterface{
				StaticConfiguration: &firecracker.StaticNetworkConfiguration{
					HostDevName: shortID,
					IPConfiguration: &firecracker.IPConfiguration{
						IfName:      "eth0",
						IPAddr:      opts.IPv4,
						Gateway:     opts.Gateway,
						Nameservers: opts.Nameservers,
					},
				},
			},
		},
		MachineCfg: firecracker_models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(opts.CPUCount),
			MemSizeMib: firecracker.Int64(opts.Memory),
		},
		VsockDevices: []firecracker.VsockDevice{
			firecracker.VsockDevice{
				ID:   shortID,
				Path: fmt.Sprintf("/tmp/%s-vsock.socket", shortID),
				CID:  3,
			},
		},
	}

	stdin := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	ctx := context.Background()
	cmd := firecracker.VMCommandBuilder{}.
		WithBin(opts.FirecrackerBin).
		WithSocketPath(config.SocketPath).
		WithStdin(stdin).
		WithStdout(stdout).
		WithStderr(stderr).
		Build(ctx)
	machineOpts := []firecracker.Opt{
		firecracker.WithProcessRunner(cmd),
	}

	machine, err := firecracker.NewMachine(ctx, config, machineOpts...)
	if err != nil {
		log.Fatalf("Error Creating Machine: %s", err)
	}

	return VM{
		ID:      id,
		Ctx:     ctx,
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
		Machine: machine,
		ShortID: shortID,
		// IPv6:    ipv6,
	}
}

func (vm VM) Start() {
	// Create a new tap device
	if out, err := exec.Command("ip", "tuntap", "add", vm.ShortID, "mode", "tap").CombinedOutput(); err != nil {
		log.Fatalf("Error Creating Tap Device: %s: %s", err, out)
	}

	// Attach the tap device to bridge
	if out, err := exec.Command("ip", "link", "set", "dev", vm.ShortID, "master", defaultBridge).CombinedOutput(); err != nil {
		log.Fatalf("Error Enslaving Tap Device: %s: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", vm.ShortID, "up").CombinedOutput(); err != nil {
		log.Fatalf("Error Upping Tap Device: %s: %s", err, out)
	}

	// Start the vm
	if err := vm.Machine.Start(vm.Ctx); err != nil {
		log.Fatalf("Error Starting Machine: %s", err)
	}
}

func (vm VM) Stop() {
	// Stop the vm
	if err := vm.Machine.StopVMM(); err != nil {
		log.Println(err)
	}

	// Delete the tap device
	if out, err := exec.Command("ip", "link", "del", vm.ShortID).CombinedOutput(); err != nil {
		log.Fatalf("Error Deleting Tap Device: %s: %s", err, out)
	}
}

func main2() {
	// vm := NewVM(DefaultOpts)
	// vm.Start()

	// vm.Machine.Wait(vm.Ctx)

	// vm.Stop()

	socketPath := "/tmp/v.sock"
	cid := 3
	port := 10000

	log.Printf("Connecting to gRPC server at vsock CID %d, port %d...", cid, port)

	// --- 1. Create the Custom Dialer ---
	// This dialer performs the Firecracker-specific handshake BEFORE gRPC starts its protocol.
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		// Step A: Connect to the Firecracker Unix socket on the host.
		log.Printf("Dialer: Connecting to Unix socket: %s", socketPath)
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Firecracker socket %s: %w", socketPath, err)
		}
		log.Println("Dialer: Unix socket connected.")

		// Step B: Send the text-based CONNECT command to Firecracker.
		connectCmd := fmt.Sprintf("CONNECT %d\n", port)
		log.Printf("Dialer: Sending command: %q", connectCmd)
		if _, err := conn.Write([]byte(connectCmd)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send CONNECT command: %w", err)
		}

		// Step C: Wait for the "OK ..." acknowledgement from Firecracker.
		reader := bufio.NewReader(conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read acknowledgement from Firecracker: %w", err)
		}

		log.Printf("Dialer: Received response: %q", response)

		// Step D: Validate the acknowledgement.
		if !strings.HasPrefix(response, "OK ") {
			conn.Close()
			return nil, fmt.Errorf("invalid response from Firecracker proxy: %s", response)
		}

		log.Println("Dialer: Handshake successful. Passing established connection to gRPC.")
		return conn, nil
	}

	// --- 1. Connect to the Server ---
	conn, err := grpc.NewClient(
		"passthrough:///firecracker-vsock-proxy", // This name is arbitrary, it's just for logging.
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("could not connect to gRPC server: %w", err)
	}
	defer conn.Close()

	log.Println("Connection established.")

	// Create a client for our Pty service.
	client := pb.NewPtyClient(conn)

	// --- 2. Start the Bidirectional Stream ---
	stream, err := client.Session(context.Background())
	if err != nil {
		log.Fatalf("could not open stream: %s", err)
	}

	// --- 3. Send the Initial Start Message ---
	// This is required by our API to initialize the PTY with a size.
	log.Println("Sending start request...")
	startReq := &pb.PtyRequest{
		Event: &pb.PtyRequest_Start{
			Start: &pb.Start{
				Size: &pb.TerminalSize{Rows: 24, Cols: 80},
			},
		},
	}
	if err := stream.Send(startReq); err != nil {
		log.Fatalf("could not send start request: %w", err)
	}

	// --- 4. Send a Command to Execute ---
	// We run a command and then 'exit' to cleanly close the shell session.
	// The '\n' is crucial – it's like pressing Enter.
	command := "ping -c 4 1.1.1.1\n"
	log.Printf("Sending command: %q", command)

	inputReq := &pb.PtyRequest{
		Event: &pb.PtyRequest_Input{
			Input: []byte(command),
		},
	}
	if err := stream.Send(inputReq); err != nil {
		log.Fatalf("could not send input request: %w", err)
	}

	// --- 6. Receive and Print All Server Output ---
	// Loop until the server closes its side of the stream (io.EOF).
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			// This is the expected, clean end of the stream.
			log.Println("Stream finished.")
			break
		}
		if err != nil {
			log.Fatalf("error receiving from stream: %w", err)
		}

		// Use a type switch to handle different server events.
		switch event := resp.Event.(type) {
		case *pb.PtyResponse_Output:
			// Write the raw PTY output directly to our console.
			os.Stdout.Write(event.Output)
		case *pb.PtyResponse_ExitCode:
			// The server sent the final exit code.
			fmt.Printf("\n--- Session ended with exit code: %d ---\n", event.ExitCode)
		}
	}

	// --- 5. Signal That We're Done Sending ---
	// This closes the client-to-server direction of the stream.
	// The server will see this as an EOF on its Recv() call.
	if err := stream.CloseSend(); err != nil {
		log.Fatalf("failed to close send stream: %w", err)
	}
	log.Println("Finished sending commands. Now waiting for output...")
}
