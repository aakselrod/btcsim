/*
 * Copyright (c) 2014-2015 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcutil"

	"math/rand"
	_ "net/http/pprof"
	"runtime"
	"time"
)

var (
	// maxConnRetries defines the number of times to retry rpc client connections
	maxConnRetries = flag.Int("maxconnretries", 30, "Maximum retries to connect to rpc client")

	// maxBlockSize defines the maximum block size to be passed as -blockmaxsize to the miner
	maxBlockSize = flag.Int("maxblocksize", 999000, "Maximum block size in bytes used by the miner")

	// maxSplit defines the maximum number of pieces to divide a utxo into
	maxSplit = flag.Int("maxsplit", 100, "Maximum number of pieces to divide a utxo into")

	// profile
	profile = flag.String("profile", "6060", "Listen address for profiling server")

	// simFilePath is the path to a YAML file containing simulation commands
	simFilePath = flag.String("simfile", "",
		"Path to the YAML file containing simulation commands")
)

var (
	// AppDataDir is the path to the working directory set using btcutil.AppDataDir
	AppDataDir = btcutil.AppDataDir("btcsim", false)

	// CertFile is the path to the certificate file of a cert-key pair used for RPC connections
	CertFile = filepath.Join(AppDataDir, "rpc.cert")

	// KeyFile is the path to the key file of a cert-key pair used for RPC connections
	KeyFile = filepath.Join(AppDataDir, "rpc.key")
)

func init() {
	flag.Parse()

	// make sure the app data dir exists
	if !fileExists(AppDataDir) {
		if err := os.Mkdir(AppDataDir, 0700); err != nil {
			log.Fatalf("Cannot create app data dir: %v", err)
		}
	}
}

func main() {
	// Seed random
	rand.Seed(time.Now().UnixNano())
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	if *profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", *profile)
			log.Printf("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			log.Printf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	simulation := NewSimulation()
	if err := simulation.readSimFile(*simFilePath); err != nil {
		log.Printf("Cannot read simfile: %v", err)
		os.Exit(1)
	}
	if err := simulation.Run(); err != nil {
		log.Printf("Simulation failed: %v", err)
		os.Exit(1)
	}
}
