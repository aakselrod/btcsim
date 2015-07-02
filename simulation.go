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
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	//"math"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	rpc "github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
)

// MissingCertPairFile is raised when one of the cert pair files is missing
type MissingCertPairFile string

func (m MissingCertPairFile) Error() string {
	return fmt.Sprintf("could not find TLS certificate pair file: %v", string(m))
}

const (
	// SimRows is the number of rows in the default curve
	SimRows = 10

	// SimUtxoCount is the starting number of utxos in the default curve
	SimUtxoCount = 2000

	// SimTxCount is the starting number of tx in the default curve
	SimTxCount = 1000
)

// Simulation contains the data required to run a simulation
type Simulation struct {
	commands []SimCommand
	/*com         *Communication*/
	nodes       map[string]*Node
	actors      map[string]*Actor
	miners      map[string]*Miner
	connections map[string][]string
	vars        map[string][]string
}

// NewSimulation returns a Simulation instance
func NewSimulation() *Simulation {
	s := &Simulation{
		/*com: NewCommunication(),*/
		nodes:       make(map[string]*Node),
		actors:      make(map[string]*Actor),
		miners:      make(map[string]*Miner),
		connections: make(map[string][]string),
		vars:        make(map[string][]string),
	}
	return s
}

// readSimFile reads and sets the commands to perform the simulation
// It defaults to a simple linear simulation
func (s *Simulation) readSimFile(simFilePath string) error {
	if simFilePath == "" {
		// if -simfile argument is omitted, use a simple
		// linear simulation as the default
		commands := make([]SimCommand, SimRows)
		for i := 0; i < SimRows; i++ {
			commands[i] = SimCommand{
				Name: "testcommand",
			}
		}
		s.commands = commands
	} else {
		commands, err := readYAML(simFilePath)
		if err != nil {
			return err
		}
		s.commands = commands
	}
	return nil
}

// Run runs the simulation in order
func (s *Simulation) Run() error {

	// re-use existing cert, key if both are present
	// if only one of cert, key is missing, exit with err message
	haveCert := fileExists(CertFile)
	haveKey := fileExists(KeyFile)
	switch {
	case haveCert && !haveKey:
		return MissingCertPairFile(KeyFile)
	case !haveCert && haveKey:
		return MissingCertPairFile(CertFile)
	case !haveCert:
		// generate new cert pair if both cert and key are missing
		err := genCertPair(CertFile, KeyFile)
		if err != nil {
			return err
		}
	}

	ntfnHandlers := &rpc.NotificationHandlers{
	/*
		OnBlockConnected: func(hash *wire.ShaHash, height int32) {
			block := &Block{
				hash:   hash,
				height: height,
			}
			select {
			case s.com.blockQueue.enqueue <- block:
			case <-s.com.exit:
			}
		},
		OnTxAccepted: func(hash *wire.ShaHash, amount btcutil.Amount) {
			s.com.timeReceived <- time.Now()
		},
	*/
	}

	unusedPort := uint16(18550)

	for _, cmd := range s.commands {
		switch cmd.Cmd {
		case "startnode":
			if cmd.Name == "" {
				log.Printf("Node name can't be blank")
				return errors.New("node name is blank")
			}
			if _, used := s.nodes[cmd.Name]; used {
				log.Printf("Name %v already used", cmd.Name)
				return errors.New("duplicate name for node")
			}
			args, err := newBtcdArgs(cmd.Name)
			if err != nil {
				log.Printf("Cannot create node args: %v", err)
				return err
			}
			logFile, err := getLogFile(args.prefix)
			if err != nil {
				log.Printf("Cannot get log file, logging disabled: %v", err)
			}
			args.Listen = fmt.Sprintf("127.0.0.1:%v", unusedPort)
			unusedPort++
			args.RPCListen = fmt.Sprintf("127.0.0.1:%v", unusedPort)
			unusedPort++
			var connNode Node
			if cmd.Name2 != "" {
				connNode, used := s.nodes[cmd.Name2]
				if !used {
					log.Printf("%v is not an existing node", cmd.Name2)
					return errors.New("node doesn't exist")
				}
				args.Extra = append(args.Extra,
					fmt.Sprintf("--addpeer=%v", (connNode.Args.(*btcdArgs)).Listen))
			}
			log.Printf("Starting node %v on simnet...", cmd.Name)
			node, err := NewNodeFromArgs(args, ntfnHandlers, logFile)
			if err != nil {
				log.Printf("%s: Cannot create node: %v", node, err)
				return err
			}
			if err := node.Start(); err != nil {
				log.Printf("%s: Cannot start node: %v", node, err)
				return err
			}
			if err := node.Connect(); err != nil {
				log.Printf("%s: Cannot connect to node: %v", node, err)
				return err
			}
			s.nodes[cmd.Name] = node
			if cmd.Name2 != "" {
				s.connections[cmd.Name] = []string{cmd.Name2}
				log.Printf("Waiting for synchronization")
				var lastHash1, lastHash2 *wire.ShaHash
				var lastHeight1, lastHeight2 int32
				for {
					hash1, height1, err := node.client.GetBestBlock()
					if err != nil {
						log.Printf("Error getting best block hash from %v: %v",
							cmd.Name, err)
						return err
					}
					hash2, height2, err := connNode.client.GetBestBlock()
					if err != nil {
						log.Printf("Error getting best block hash from %v: %v",
							cmd.Name2, err)
						return err
					}
					if lastHash1 == hash1 && lastHash2 == hash2 &&
						lastHeight1 == height1 && lastHeight2 == height2 {
						log.Printf("Synchronization stuck: %v at %v (%v); %v at %v (%v)",
							cmd.Name, height1, hash1.String(), cmd.Name2, height2,
							hash2.String())
						return err
					}
					if hash1.String() == hash2.String() && height1 == height2 {
						log.Printf("%v and %v are synchronized at height %v (%v)",
							cmd.Name, cmd.Name2, height1, hash1.String())
						break
					}
					time.Sleep(time.Second)
					lastHash1 = hash1
					lastHash2 = hash2
					lastHeight1 = height1
					lastHeight2 = height2
				}
			}
		case "startwallet":
			if cmd.Name == "" {
				log.Printf("Wallet name can't be blank")
				return errors.New("wallet name is blank")
			}
			if cmd.Name2 == "" {
				log.Printf("Wallet must connect to an existing node")
				return errors.New("no node name passed to wallet")
			}
			if _, used := s.nodes[cmd.Name]; used {
				log.Printf("Name %v already used", cmd.Name)
				return errors.New("duplicate name for wallet")
			}
			connNode, used := s.nodes[cmd.Name2]
			if !used {
				log.Printf("%v is not an existing node", cmd.Name2)
				return errors.New("node doesn't exist")
			}
			log.Printf("Starting wallet %v on simnet...", cmd.Name)
			actor, err := NewActor(connNode, unusedPort)
			unusedPort++
			if err != nil {
				log.Printf("%s: Cannot create actor: %v", cmd.Name, err)
				return err
			}
			if err := actor.Start(os.Stderr, os.Stdout); err != nil {
				log.Printf("%s: Cannot start actor: %v", actor, err)
				actor.Shutdown()
				return err
			}
			s.actors[cmd.Name] = actor
			s.connections[cmd.Name] = []string{cmd.Name2}
		case "startminer":
			if cmd.Name == "" {
				log.Printf("Miner name can't be blank")
				return errors.New("miner name is blank")
			}
			if cmd.Name2 == "" {
				log.Printf("Miner must connect to an existing node")
				return errors.New("no node name passed to miner")
			}
			if _, used := s.miners[cmd.Name]; used {
				log.Printf("Name %v already used", cmd.Name)
				return errors.New("duplicate name for miner")
			}
			connNode, used := s.nodes[cmd.Name2]
			if !used {
				log.Printf("%v is not an existing node", cmd.Name2)
				return errors.New("node doesn't exist")
			}
			if cmd.Var == "" {
				log.Printf("Miner %v must be started with mining addresses", cmd.Name)
				return errors.New("no mining addresses passed for miner")
			}
			addrStrings, used := s.vars[cmd.Var]
			if !used {
				log.Printf("Variable %v is not set", cmd.Var)
				return errors.New("variable containing mining addresses isn't set")
			}
			miningAddrs := make([]btcutil.Address, len(addrStrings))
			for i, addr := range addrStrings {
				miningAddr, err := btcutil.DecodeAddress(addr, &chaincfg.SimNetParams)
				if err != nil {
					log.Printf("Couldn't parse address %v", addr)
					return err
				}
				miningAddrs[i] = miningAddr
			}
			log.Printf("Starting miner %v on simnet...", cmd.Name)
			listenPort := unusedPort
			unusedPort++
			rpcListenPort := unusedPort
			unusedPort++
			miner, err := NewMiner(miningAddrs, *connNode, listenPort, rpcListenPort)
			if err != nil {
				log.Printf("Cannot start miner: %v", err)
				return err
			}
			s.miners[cmd.Name] = miner
			s.connections[cmd.Name] = []string{cmd.Name2}
			log.Printf("Waiting for synchronization")
			var lastHash1, lastHash2 *wire.ShaHash
			var lastHeight1, lastHeight2 int32
			for {
				hash1, height1, err := miner.client.GetBestBlock()
				if err != nil {
					log.Printf("Error getting best block hash from %v: %v",
						cmd.Name, err)
					return err
				}
				hash2, height2, err := connNode.client.GetBestBlock()
				if err != nil {
					log.Printf("Error getting best block hash from %v: %v",
						cmd.Name2, err)
					return err
				}
				if lastHash1 == hash1 && lastHash2 == hash2 &&
					lastHeight1 == height1 && lastHeight2 == height2 {
					log.Printf("Synchronization stuck: %v at %v (%v); %v at %v (%v)",
						cmd.Name, height1, hash1.String(), cmd.Name2, height2,
						hash2.String())
					return err
				}
				if hash1.String() == hash2.String() && height1 == height2 {
					log.Printf("%v and %v are synchronized at height %v (%v)",
						cmd.Name, cmd.Name2, height1, hash1.String())
					break
				}
				time.Sleep(time.Second)
				lastHash1 = hash1
				lastHash2 = hash2
				lastHeight1 = height1
				lastHeight2 = height2
			}
		case "connect":
			if cmd.Name == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			if cmd.Name2 == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			var client1 *rpc.Client
			node1, used := s.nodes[cmd.Name]
			if !used {
				miner1, used := s.miners[cmd.Name]
				if !used {
					log.Printf("%v is not an existing node or miner", cmd.Name)
					return errors.New("node or miner does not exist")
				} else {
					client1 = miner1.client
				}
			} else {
				client1 = node1.client
			}
			node2, used := s.nodes[cmd.Name2]
			if !used {
				log.Printf("%v is not an existing node", cmd.Name2)
				return errors.New("node does not exist")
			}
			alreadyConnected := false
			if conns, used := s.connections[cmd.Name]; used {
				for _, conn := range conns {
					if conn == cmd.Name2 {
						alreadyConnected = true
					}
				}
			}
			if conns, used := s.connections[cmd.Name2]; used {
				for _, conn := range conns {
					if conn == cmd.Name {
						alreadyConnected = true
					}
				}
			}
			if alreadyConnected {
				log.Printf("%v is already connected to %v", cmd.Name, cmd.Name2)
				return errors.New("nodes already connected to each other")
			}
			log.Printf("Connecting %v to %v", cmd.Name, cmd.Name2)
			client1.AddNode(node2.Args.(*btcdArgs).Listen, rpc.ANAdd)
			if _, used := s.connections[cmd.Name]; used {
				s.connections[cmd.Name] = append(s.connections[cmd.Name], cmd.Name2)
			} else {
				s.connections[cmd.Name] = []string{cmd.Name2}
			}
			log.Printf("Waiting for synchronization")
			var lastHash1, lastHash2 *wire.ShaHash
			var lastHeight1, lastHeight2 int32
			for {
				hash1, height1, err := client1.GetBestBlock()
				if err != nil {
					log.Printf("Error getting best block hash from %v: %v",
						cmd.Name, err)
					return err
				}
				hash2, height2, err := node2.client.GetBestBlock()
				if err != nil {
					log.Printf("Error getting best block hash from %v: %v",
						cmd.Name2, err)
					return err
				}
				if lastHash1 == hash1 && lastHash2 == hash2 &&
					lastHeight1 == height1 && lastHeight2 == height2 {
					log.Printf("Synchronization stuck: %v at %v (%v); %v at %v (%v)",
						cmd.Name, height1, hash1.String(), cmd.Name2, height2,
						hash2.String())
					return err
				}
				if hash1.String() == hash2.String() && height1 == height2 {
					log.Printf("%v and %v are synchronized at height %v (%v)",
						cmd.Name, cmd.Name2, height1, hash1.String())
					break
				}
				time.Sleep(time.Second)
				lastHash1 = hash1
				lastHash2 = hash2
				lastHeight1 = height1
				lastHeight2 = height2
			}
		case "disconnect":
			if cmd.Name == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			if cmd.Name2 == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			var client1 *rpc.Client
			var listen1 string
			node1, used := s.nodes[cmd.Name]
			if !used {
				miner1, used := s.miners[cmd.Name]
				if !used {
					log.Printf("%v is not an existing node or miner", cmd.Name)
					return errors.New("node or miner does not exist")
				} else {
					client1 = miner1.client
					listen1 = miner1.Args.(*btcdArgs).Listen
				}
			} else {
				client1 = node1.client
				listen1 = node1.Args.(*btcdArgs).Listen
			}
			node2, used := s.nodes[cmd.Name2]
			if !used {
				log.Printf("%v is not an existing node", cmd.Name2)
				return errors.New("node does not exist")
			}
			if conns, used := s.connections[cmd.Name]; used {
				var updatedConns []string
				for _, conn := range conns {
					if conn == cmd.Name2 {
						log.Printf("Disconnecting %v from %v", cmd.Name, cmd.Name2)
						client1.AddNode(node2.Args.(*btcdArgs).Listen, rpc.ANRemove)
					} else {
						updatedConns = append(updatedConns, conn)
					}
				}
				s.connections[cmd.Name] = updatedConns
			}
			if conns, used := s.connections[cmd.Name2]; used {
				var updatedConns []string
				for _, conn := range conns {
					if conn == cmd.Name {
						log.Printf("Disconnecting %v from %v", cmd.Name2, cmd.Name)
						node2.client.AddNode(listen1, rpc.ANRemove)
					} else {
						updatedConns = append(updatedConns, conn)
					}
				}
				s.connections[cmd.Name2] = updatedConns
			}
		case "genaddresses":
			if cmd.Name == "" {
				log.Printf("Wallet name can't be blank")
				return errors.New("wallet name is blank")
			}
			wallet, used := s.actors[cmd.Name]
			if !used {
				log.Printf("%v is not an existing wallet", cmd.Name)
				return errors.New("wallet does not exist")
			}
			if cmd.Num == 0 {
				log.Printf("Must specify a nonzero number of addresses to generate")
				return errors.New("no addresses to generate")
			}
			if cmd.Var == "" {
				log.Printf("Variable name can't be blank")
				return errors.New("variable name is blank")
			}
			log.Printf("Generating %v addresses in %v", cmd.Num, cmd.Name)
			s.vars[cmd.Var] = make([]string, cmd.Num)
			for i := uint32(0); i < cmd.Num; i++ {
				addr, err := wallet.client.GetNewAddress("default")
				if err != nil {
					log.Printf("Error generating address: %v", err)
					return err
				}
				s.vars[cmd.Var][i] = addr.String()
			}
		case "genblocks":
			if cmd.Name == "" {
				log.Printf("Miner name can't be blank")
				return errors.New("miner name is blank")
			}
			miner, used := s.miners[cmd.Name]
			if !used {
				log.Printf("%v is not an existing miner", cmd.Name)
				return errors.New("miner does not exist")
			}
			if cmd.Num == 0 {
				log.Printf("Must specify a nonzero number of blocks to generate")
				return errors.New("no blocks to generate")
			}
			log.Printf("Generating %v blocks on %v", cmd.Num, cmd.Name)
			_, err := miner.client.Generate(cmd.Num)
			if err != nil {
				log.Printf("Error generating blocks: %v", err)
				return err
			}
		case "gentxs":
		case "debuglevel":
			if cmd.Name == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			var client *rpc.Client
			node, used := s.nodes[cmd.Name]
			if !used {
				miner, used := s.miners[cmd.Name]
				if !used {
					log.Printf("%v is not an existing node or miner", cmd.Name)
					return errors.New("node or miner does not exist")
				} else {
					client = miner.client
				}
			} else {
				client = node.client
			}
			log.Printf("Setting debuglevel for %v to %v", cmd.Name, cmd.StrArg)
			result, err := client.DebugLevel(cmd.StrArg)
			if result != "Done." || err != nil {
				log.Printf("Error setting debuglevel: %v (%v)", result, err.Error())
				return err
			}
		case "shell":
			if cmd.StrArg == "" {
				log.Printf("Command can't be blank")
				return errors.New("command is blank")
			}
			log.Printf("Executing command: %v", cmd.StrArg)
			shellCmd := exec.Command("bash", "-c", cmd.StrArg)
			out, err := shellCmd.CombinedOutput()
			log.Printf(string(out))
			if err != nil {
				log.Printf("Error executing command: %v", err)
				return errors.New("error executing command")
			}
			if cmd.Var != "" {
				s.vars[cmd.Var] = strings.Split(string(out), "\n")
			}
		case "savechain":
			if cmd.Name == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			if cmd.StrArg == "" {
				log.Printf("Filename can't be blank")
				return errors.New("filename is blank")
			}
			var client *rpc.Client
			node, used := s.nodes[cmd.Name]
			if !used {
				miner, used := s.miners[cmd.Name]
				if !used {
					log.Printf("%v is not an existing node or miner", cmd.Name)
					return errors.New("node or miner does not exist")
				} else {
					client = miner.client
				}
			} else {
				client = node.client
			}
			bc, err := client.GetBlockCount()
			if err != nil {
				log.Printf("Error getting block count: %v", err)
				return errors.New("can't get block count")
			}
			fo, err := os.Create(cmd.StrArg)
			if err != nil {
				log.Printf("Error creating file: %v", err)
				return errors.New("can't create file")
			}
			err = binary.Write(fo, binary.BigEndian, &bc)
			if err != nil {
				fo.Close()
				log.Printf("Can't write block count to file: %v", err)
				return errors.New("can't write block count to file")
			}
			log.Printf("Writing %v blocks to %v", bc, cmd.StrArg)
			for height := int64(1); height <= bc; height++ {
				hash, err := client.GetBlockHash(height)
				if err != nil {
					fo.Close()
					log.Printf("Error getting block hash for block %v", height)
					return errors.New("can't get block hash")
				}
				block, err := client.GetBlock(hash)
				if err != nil {
					fo.Close()
					log.Printf("Error getting block %v(%v)", height, hash)
					return errors.New("can't get block")
				}
				blockBytes, err := block.Bytes()
				if err != nil {
					fo.Close()
					log.Printf("Error getting bytes for block %v: %v", height, err)
					return errors.New("can't get bytes for block")
				}
				bs := int64(len(blockBytes))
				err = binary.Write(fo, binary.BigEndian, &bs)
				if err != nil {
					fo.Close()
					log.Printf("Can't write block size to file: %v", err)
					return errors.New("can't write block size to file")
				}
				_, err = fo.Write(blockBytes)
				if err != nil {
					fo.Close()
					log.Printf("Can't write block %v to file: %v", height, err)
					return errors.New("can't write block to file")
				}
			}
			fo.Close()
		case "loadchain":
			if cmd.Name == "" {
				log.Printf("Miner or node name can't be blank")
				return errors.New("miner or node name is blank")
			}
			if cmd.StrArg == "" {
				log.Printf("Filename can't be blank")
				return errors.New("filename is blank")
			}
			var client *rpc.Client
			node, used := s.nodes[cmd.Name]
			if !used {
				miner, used := s.miners[cmd.Name]
				if !used {
					log.Printf("%v is not an existing node or miner", cmd.Name)
					return errors.New("node or miner does not exist")
				} else {
					client = miner.client
				}
			} else {
				client = node.client
			}
			fi, err := os.Open(cmd.StrArg)
			if err != nil {
				log.Printf("Error opening file: %v", err)
				return errors.New("can't open file")
			}
			var bc int64
			err = binary.Read(fi, binary.BigEndian, &bc)
			if err != nil {
				fi.Close()
				log.Printf("Can't read block count from file: %v", err)
				return errors.New("can't read block count from file")
			}
			log.Printf("Reading %v blocks from %v", bc, cmd.StrArg)
			for height := int64(1); height <= bc; height++ {
				var bs int64
				err = binary.Read(fi, binary.BigEndian, &bs)
				if err != nil {
					fi.Close()
					log.Printf("Can't read block size from file: %v", err)
					return errors.New("can't read block size from file")
				}
				blockBytes := make([]byte, bs)
				_, err := fi.Read(blockBytes)
				if err != nil {
					fi.Close()
					log.Printf("Can't read block %v from file: %v", height, err)
					return errors.New("can't read block from file")
				}
				block, err := btcutil.NewBlockFromBytes(blockBytes)
				if err != nil {
					fi.Close()
					log.Printf("Can't convert bytes into block %v: %v", height, err)
					return errors.New("can't convert bytes into block")
				}
				err = client.SubmitBlock(block, nil)
				if err != nil {
					fi.Close()
					log.Printf("Error submitting block %v: %v", height, err)
					return errors.New("can't submit block")
				}
			}
			fi.Close()
		case "savetx":
		case "loadtx":
		}
	}

	/*

		log.Println("Starting node on simnet...")
		args, err := newBtcdArgs("node")
		if err != nil {
			log.Printf("Cannot create node args: %v", err)
			return err
		}
		logFile, err := getLogFile(args.prefix)
		if err != nil {
			log.Printf("Cannot get log file, logging disabled: %v", err)
		}
		node, err := NewNodeFromArgs(args, ntfnHandlers, logFile)
		if err != nil {
			log.Printf("%s: Cannot create node: %v", node, err)
			return err
		}
		if err := node.Start(); err != nil {
			log.Printf("%s: Cannot start node: %v", node, err)
			return err
		}
		if err := node.Connect(); err != nil {
			log.Printf("%s: Cannot connect to node: %v", node, err)
			return err
		}

		// Register for block notifications.
		if err := node.client.NotifyBlocks(); err != nil {
			log.Printf("%s: Cannot register for block notifications: %v", node, err)
			return err
		}

		// Register for transaction notifications
		if err := node.client.NotifyNewTransactions(false); err != nil {
			log.Printf("%s: Cannot register for transactions notifications: %v", node, err)
			return err
		}

		for i := 0; i < *numActors; i++ {
			a, err := NewActor(node, uint16(18557+i))
			if err != nil {
				log.Printf("%s: Cannot create actor: %v", a, err)
				continue
			}
			s.actors = append(s.actors, a)
		}

		// if we receive an interrupt, proceed to shutdown
		addInterruptHandler(func() {
			close(s.com.exit)
		})

		// Start simulation.
		tpsChan, tpbChan := s.com.Start(s.actors, node, s.txCurve)
		s.com.WaitForShutdown()

		tps, ok := <-tpsChan
		if ok && !math.IsNaN(tps) {
			log.Printf("Average transactions per sec: %.2f", tps)
		}

		tpb, ok := <-tpbChan
		if ok && tpb > 0 {
			log.Printf("Maximum transactions per block: %v", tpb)
		}
	*/
	return nil
}
