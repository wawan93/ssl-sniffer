package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sniffer/pkg/sniff"
)

func main() {
	device := flag.String("device", "eth0", "")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	messages, err := sniff.Sniff(ctx, *device)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for msg := range messages {
			log.Println(msg)
		}
	}()

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)
	<-termChan

	cancel()
}
