// go:build linux
package main

import (
	"context"
	"io"
	"log"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/mdlayher/vsock"
	_ "google.golang.org/genproto/protobuf/ptype" // ambigious imports bullshit
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/adv1k/linux-playground/init/pb"
)

const vsockPort = 10000

type PtyServer struct {
	pb.UnimplementedPtyServer
}

func (s *PtyServer) Session(stream grpc.BidiStreamingServer[pb.PtyRequest, pb.PtyResponse]) error {
	log.Println("New terminal session requested")

	// The first message from the client MUST be a Start message.
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to receive start message: %v", err)
	}
	startEvent := req.GetStart()
	if startEvent == nil {
		return status.Error(codes.InvalidArgument, "expected first message to be 'start'")
	}
	initialSize := startEvent.GetSize()

	// Start the default shell
	// TODO: Get the default shell from /etc/passwords
	cmd := exec.Command("/bin/bash", "-i")
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(initialSize.Rows),
		Cols: uint16(initialSize.Cols),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to start pty: %v", err)
	}
	defer ptmx.Close()
	log.Printf("PTY started for command: %s", cmd.String())

	// Use a cancellable context to coordinate goroutine shutdown.
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	var wg sync.WaitGroup

	// Goroutine: Sender
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel() // If PTY reading stops, cancel the context to stop the other goroutine.

		var buf []byte
		for {
			// Check if context was cancelled by the other goroutine first.
			if ctx.Err() != nil {
				return
			}

			buf = make([]byte, 4096)
			n, err := ptmx.Read(buf)
			// io.EOF means the process in the PTY has exited.
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from PTY: %v", err)
				}
				return // Exit goroutine.
			}

			if err := stream.Send(&pb.PtyResponse{
				Event: &pb.PtyResponse_Output{Output: buf[:n]},
			}); err != nil {
				log.Printf("Error sending PTY output to client: %v", err)
				return // Exit goroutine if client stream is broken.
			}
		}
	}()

	// Goroutine: Receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel() // If client reading stops, cancel to stop the other goroutine.

		for {
			// Check if context was cancelled by the other goroutine first.
			if ctx.Err() != nil {
				return
			}

			req, err := stream.Recv()
			// io.EOF means the client has closed its sending stream.
			if err != nil {
				if err != io.EOF && status.Code(err) != codes.Canceled {
					log.Printf("Error receiving from client: %v", err)
				}
				return // Exit goroutine.
			}

			// Use a type switch to handle different client events.
			switch event := req.Event.(type) {
			case *pb.PtyRequest_Input:
				if _, err := ptmx.Write(event.Input); err != nil {
					log.Printf("Error writing to PTY: %v", err)
					return
				}
			case *pb.PtyRequest_Resize:
				size := event.Resize
				if err := pty.Setsize(ptmx, &pty.Winsize{
					Rows: uint16(size.Rows),
					Cols: uint16(size.Cols),
				}); err != nil {
					log.Printf("Error setting PTY window size: %v", err)
				}
			default:
				log.Printf("Warning: received unknown message type from client")
			}
		}
	}()

	// Wait for the context to be cancelled, which means one of the goroutines has exited.
	<-ctx.Done()

	// Ensure PTY is closed, which will unblock the read goroutine if it's still running.
	ptmx.Close()

	// Wait for all goroutines to fully finish their cleanup.
	wg.Wait()

	var exitCode uint32
	if err := cmd.Wait(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			// This is a different kind of error, like a problem starting the command.
			log.Printf("Error waiting for command (not an ExitError): %v", err)
			return status.Errorf(codes.Internal, "failed to wait for command: %v", err)
		}

		// This is the normal case for a non-zero exit or a signal termination.
		// We need to get the underlying syscall.WaitStatus.
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			log.Printf("Underlying error not a syscall.WaitStatus: %T", exitErr.Sys())
			// Can't get a specific code, so we send a generic failure code.
			exitCode = 1
		} else {
			if ws.Exited() {
				// Process exited normally with a non-zero status.
				exitCode = uint32(ws.ExitStatus())
			} else if ws.Signaled() {
				// Process was killed by a signal.
				// Follow the shell convention: 128 + signal number.
				exitCode = uint32(128 + ws.Signal())
			} else {
				// This is a rare case, but good to handle.
				// The process was stopped or continued (e.g. by a debugger).
				log.Printf("Command stopped or continued, not exited: %v", ws)
				exitCode = 1 // Generic failure
			}
		}
	} else {
		// The command exited successfully with status 0.
		exitCode = 0
	}

	// Send the final exit code to the client. This is the last message.
	log.Printf("Session ended with exit code: %d", exitCode)
	if err := stream.Send(&pb.PtyResponse{ // Corrected to use ptypb as per other examples
		Event: &pb.PtyResponse_ExitCode{ExitCode: exitCode},
	}); err != nil {
		log.Printf("Failed to send final exit code: %v", err)
	}

	log.Println("Session cleanup complete")
	return nil
}

func startPtyServer() {
	conn, err := vsock.Listen(vsockPort, &vsock.Config{})
	if err != nil {
		log.Fatalf("failed to listen on vsock: %v", err)
	}
	defer conn.Close()

	s := grpc.NewServer()
	pb.RegisterPtyServer(s, &PtyServer{})

	log.Printf("gRPC PTY server listening on vsock port %d", vsockPort)
	if err := s.Serve(conn); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
