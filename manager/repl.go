//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/adv1k/linux-playground/init/pb"
	"golang.org/x/term" // <-- IMPORT THIS
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ... (Your VmOptions, VM struct, NewVM, Start, Stop functions remain exactly the same) ...
// ... VmOptions ...
// ... VM struct ...
// ... NewVM func ...
// ... Start func ...
// ... Stop func ...

// streamWriter is a helper struct that allows us to use io.Copy with a gRPC stream.
// It implements the io.Writer interface.
type streamWriter struct {
	stream pb.Pty_SessionClient
}

func (w *streamWriter) Write(p []byte) (n int, err error) {
	if err := w.stream.Send(&pb.PtyRequest{
		Event: &pb.PtyRequest_Input{
			Input: p,
		},
	}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func main() {
	// // --- 1. SETUP THE VM ---
	// log.Println("Creating and starting new VM...")
	// vm := NewVM(DefaultOpts)
	// vm.Start()
	// // Ensure the VM is stopped and its resources are cleaned up when main exits.
	// defer vm.Stop()
	// log.Printf("VM %s started.", vm.ShortID)

	// --- 2. SETUP THE LOCAL TERMINAL ---
	// Check if we are running in an actual terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Fatal("This REPL must be run in a terminal.")
	}

	// Put the local terminal into raw mode. This is crucial for an interactive shell.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("failed to set terminal to raw mode: %v", err)
	}
	// VERY IMPORTANT: Restore the terminal state on exit.
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Get initial terminal size.
	cols, rows, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("failed to get terminal size: %v", err)
	}

	// --- 3. SETUP GRPC CONNECTION ---
	// Get the dynamic socket paths from the VM configuration.
	socketPath := "/tmp/v.sock"
	port := 10000 // Your server listens on this port inside the guest

	log.Printf("Connecting to gRPC server via Firecracker proxy at %s...", socketPath)

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		// (The custom dialer logic for the Firecracker proxy remains the same)
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, err
		}
		connectCmd := fmt.Sprintf("CONNECT %d\n", port)
		if _, err := conn.Write([]byte(connectCmd)); err != nil {
			conn.Close()
			return nil, err
		}
		response, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if !strings.HasPrefix(response, "OK ") {
			conn.Close()
			return nil, fmt.Errorf("invalid proxy response: %s", response)
		}
		return conn, nil
	}

	conn, err := grpc.NewClient(
		"passthrough:///firecracker-vsock-proxy",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("could not connect to gRPC server: %w", err)
	}
	defer conn.Close()

	log.Println("Connection established. Starting PTY session.")
	client := pb.NewPtyClient(conn)
	stream, err := client.Session(context.Background())
	if err != nil {
		log.Fatalf("could not open stream: %s", err)
	}

	// --- 4. START THE REPL ---
	// Send the initial start message with the current terminal size.
	if err := stream.Send(&pb.PtyRequest{
		Event: &pb.PtyRequest_Start{
			Start: &pb.Start{
				Size: &pb.TerminalSize{Rows: uint32(rows), Cols: uint32(cols)},
			},
		},
	}); err != nil {
		log.Fatalf("could not send start request: %w", err)
	}

	// Use a context to coordinate goroutine shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Goroutine 1: Read from gRPC stream and write to stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel() // If this loop ends, cancel the context to stop others.
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					log.Printf("Error receiving from stream: %v", err)
				}
				return
			}
			switch event := resp.Event.(type) {
			case *pb.PtyResponse_Output:
				os.Stdout.Write(event.Output)
			case *pb.PtyResponse_ExitCode:
				// The remote process has exited. We're done.
				return
			}
		}
	}()

	// Goroutine 2: Read from stdin and write to gRPC stream
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		// When this goroutine finishes, close the client-side sending stream.
		defer stream.CloseSend()
		// io.Copy will block until stdin is closed (e.g., Ctrl+D) or an error occurs.
		io.Copy(&streamWriter{stream: stream}, os.Stdin)
	}()

	// Goroutine 3: Handle terminal resize events
	wg.Add(1)
	go func() {
		defer wg.Done()
		sigwinch := make(chan os.Signal, 1)
		signal.Notify(sigwinch, syscall.SIGWINCH)
		// Don't stop the signal handler, let the context handle shutdown.
		for {
			select {
			case <-sigwinch:
				c, r, err := term.GetSize(int(os.Stdin.Fd()))
				if err == nil {
					stream.Send(&pb.PtyRequest{
						Event: &pb.PtyRequest_Resize{
							Resize: &pb.TerminalSize{Rows: uint32(r), Cols: uint32(c)},
						},
					})
				}
			case <-ctx.Done():
				// The session has ended, stop listening for resize events.
				return
			}
		}
	}()

	// Wait for the context to be cancelled (which happens when the output stream ends).
	<-ctx.Done()
	log.Println("Session ended. Cleaning up...")

	// Wait for all goroutines to finish gracefully.
	wg.Wait()
}
