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
	"fmt"
	"log"

	//"github.com/btcsuite/btcd/wire"
	//rpc "github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
)

// Miner holds all the core features required to register, run, control,
// and kill a cpu-mining btcd instance.
type Miner struct {
	*Node
}

// NewMiner starts a cpu-mining enabled btcd instane and returns an rpc client
// to control it.
func NewMiner(miningAddrs []btcutil.Address, connNode Node, listen uint16,
	rpcListen uint16) (*Miner, error) {

	log.Println("Starting miner on simnet...")
	args, err := newBtcdArgs("miner")
	if err != nil {
		return nil, err
	}

	// set miner args - it listens on a different port
	// because a node is already running on the default port
	args.Listen = fmt.Sprintf("127.0.0.1:%v", listen)
	args.RPCListen = fmt.Sprintf("127.0.0.1:%v", rpcListen)
	// need to log mining details, so set debuglevel
	args.DebugLevel = "MINR=trace"
	// if passed, set blockmaxsize to allow mining large blocks
	args.Extra = []string{fmt.Sprintf("--blockmaxsize=%d", *maxBlockSize)}
	// set the actors' mining addresses
	for _, addr := range miningAddrs {
		// make sure addr was initialized
		if addr != nil {
			args.Extra = append(args.Extra, "--miningaddr="+addr.EncodeAddress())
		}
	}

	args.Extra = append(args.Extra, fmt.Sprintf("--addpeer=127.0.0.1:%v",
		(connNode.Args.(*btcdArgs)).Listen))

	logFile, err := getLogFile(args.prefix)
	if err != nil {
		log.Printf("Cannot get log file, logging disabled: %v", err)
	}
	node, err := NewNodeFromArgs(args, nil /*ntfnHandlers*/, logFile)

	miner := &Miner{
		Node: node,
	}
	if err := node.Start(); err != nil {
		log.Printf("%s: Cannot start mining node: %v", miner, err)
		return nil, err
	}
	if err := node.Connect(); err != nil {
		log.Printf("%s: Cannot connect to node: %v", miner, err)
		return nil, err
	}

	return miner, nil
}

// Generate makes the CPU miner mine the requested number of blocks
func (m *Miner) Generate(numBlocks uint32) error {
	if _, err := m.client.Generate(numBlocks); err != nil {
		log.Printf("%s: Cannot generate %d blocks: %v", m, numBlocks, err)
		return err
	}
	return nil
}
