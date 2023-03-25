package main

import (
	// Add local server package
	"flag"
	"fmt"
	"os"

	server "github.com/infrabuilder/transplaneur/server"
)

var version string

func main() {

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	versionFlag := flag.Bool("V", false, "Print version")
	versionLongFlag := flag.Bool("version", false, "Print version")
	helpFlag := flag.Bool("h", false, "Print help")
	helpLongFlag := flag.Bool("help", false, "Print help")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseLongFlag := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	if *versionFlag || *versionLongFlag {
		printVersion()
		return
	}

	if *helpFlag || *helpLongFlag {
		printUsage()
		return
	}

	debug := *verboseFlag || *verboseLongFlag
	if debug {
		fmt.Println("Debug mode enabled")
	}

	switch os.Args[1] {
	case "server":
		server.Start()
	case "client":
		// Implement client subcommand
	case "version":
		printVersion()
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  myprogram server")
	fmt.Println("  myprogram client")
	fmt.Println("  myprogram version")
	fmt.Println("  myprogram help")
	fmt.Println("\nFlags:")
	fmt.Println("  -V, --version     Print version")
	fmt.Println("  -h, --help        Print help")
	fmt.Println("  -v, --verbose     Enable verbose output")
}

func printVersion() {
	// If version is not set, print "dev"
	if version == "" {
		version = "dev"
	}

	fmt.Println(version)
}
