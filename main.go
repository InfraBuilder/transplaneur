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

	globalFlagSet := flag.NewFlagSet("global", flag.ExitOnError)

	versionFlag := globalFlagSet.Bool("V", false, "Print version")
	versionLongFlag := globalFlagSet.Bool("version", false, "Print version")
	helpFlag := globalFlagSet.Bool("h", false, "Print help")
	helpLongFlag := globalFlagSet.Bool("help", false, "Print help")
	verboseFlag := globalFlagSet.Bool("v", false, "Enable verbose output")
	verboseLongFlag := globalFlagSet.Bool("verbose", false, "Enable verbose output")

	globalFlagSet.Parse(os.Args[1:])

	if *versionFlag || *versionLongFlag {
		printVersion()
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

		if *helpFlag || *helpLongFlag {
			printUsage()
			return
		}

		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	var command string = os.Args[0]
	fmt.Println("Usage:")
	fmt.Printf("\t%s server\n", command)
	fmt.Printf("\t%s client\n", command)
	fmt.Printf("\t%s version\n", command)
	fmt.Printf("\t%s help\n", command)
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
