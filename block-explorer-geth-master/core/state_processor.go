// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"os/exec"
	"time"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	common.CurrentBlockNumber=block.Number().String()
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		common.TxNums+=1
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

/*
	if common.TxNums>=693394{
		fmt.Printf("\n=======Tx====================\n")
		common.TxGapCounter+=1
		fmt.Println("TxChunk:",block.Number().String(),"TxGapCounter:",common.TxGapCounter)
		common.TxNums=0
		t:=time.Now()
		fmt.Printf("TxGap:Now Time %d:%d:%d\n",t.Hour(),t.Minute(),t.Second())
		var ExecTime=(t.UnixNano()-common.LaunchTime)
		fmt.Println("TxGap:TotalTime:",(ExecTime/1e9)/60,"mins ",ExecTime/1e9,"s")
		fmt.Printf("===========================\n")
	}*/

	if common.CallNums>=(155*1e4){
	//if common.StateWriteMap[block.Number().Int64()]{
		common.StateWriteFlag=true
		fmt.Printf("\n=========CallContract==========\n")
		common.CallGapCounter+=1
		fmt.Println("CallContractChunk:",block.Number().String(),"CallGapCounter:",common.CallGapCounter)
		common.CallNums=0
		t:=time.Now()
		fmt.Printf("CallGap:Now Time %d:%d:%d\n",t.Hour(),t.Minute(),t.Second())
		var ExecTime=(t.UnixNano()-common.LaunchTime)
		fmt.Println("CallGap:TotalTime:",(ExecTime/1e9)/60,"mins ",ExecTime/1e9,"s")
		fmt.Printf("===========================\n")
	}

	//add
	if block.Number().Int64()>4999999-300&&block.Number().Int64()<5000000{
		common.StateWriteFlag=true
	}
	//if block.Number().String()=="3697138"{
	if block.Number().String()=="5100000"{
		fmt.Println("TxNums:",common.TxNums,"\nCall Nums:",common.CallNums)
		fmt.Printf("StartTIme %d:%d:%d",common.StartTime.Hour(),common.StartTime.Minute(),common.StartTime.Second())
		t:=time.Now()
		fmt.Printf("EndTime %d:%d:%d\n",t.Hour(),t.Minute(),t.Second())
		fmt.Println("Compelete Height:",block.Number().String())
		var ExecTime=(time.Now().UnixNano()-common.LaunchTime)
		fmt.Println("TotalTime:",(ExecTime/1e9)/60,"mins ",ExecTime/1e9,"s")
		fmt.Println("TimeRet:",common.TmpArray)
		for{
			time.Sleep(99999)
		}
	}
	//DispatchTheTask(block.Number().Int64())
    //add new
	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	//add new by hzy 20-4-30
	vmenv.SetTxStart(true)
	//add end
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, err
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())

	return receipt, err
}

//add new by hzy 4-22
//remote exec command on slave
func runCmd(addr string,CmdStr string){
	time.Sleep(30*time.Second)
	fmt.Println(addr, " ",CmdStr)
	var stdOut, stdErr bytes.Buffer
	cmd := exec.Command( "ssh", addr, "rm -rf data1" )
	cmd = exec.Command( "ssh", addr, CmdStr )
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	if err := cmd.Run(); err != nil {
		fmt.Printf( "cmd exec failed: %s : %s", fmt.Sprint( err ), stdErr.String() )
	}
	//fmt.Println(stdOut.String())
}
//end

//add by hzy 20-10-3
//To exec the sync process on slave
func DispatchTheTask(paramBlockNumber int64){
	var BlockNumber=paramBlockNumber
	if BlockNumber==3000010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 3000001 --hzystail 3200000 >log"
		fmt.Println("On root@slave1 With " + StrCmd)
		go runCmd("root@slave1",StrCmd)
	}else if BlockNumber==3200010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 3200001 --hzystail 3400000 >log"
		fmt.Println("On root@slave2 With " + StrCmd)
		go runCmd("root@slave2",StrCmd)
	}else if BlockNumber==3400010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 3400001 --hzystail 3600000 >log"
		fmt.Println("On root@slave3 With " + StrCmd)
		go runCmd("root@slave3",StrCmd)
	}else if BlockNumber==3600010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 3600001 --hzystail 3800000 >log"
		fmt.Println("On root@slave4 With " + StrCmd)
		go runCmd("root@slave4",StrCmd)
	}else if BlockNumber==3800010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 3800001 --hzystail 4000000 >log"
		fmt.Println("On root@slave5 With " + StrCmd)
		go runCmd("root@slave5",StrCmd)
	}else if BlockNumber==4000010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 4000001 --hzystail 4200000 >log"
		fmt.Println("On root@slave6 With " + StrCmd)
		go runCmd("root@slave6",StrCmd)
	}else if BlockNumber==4200010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 4200001 --hzystail 4400000 >log"
		fmt.Println("On root@slave7 With " + StrCmd)
		go runCmd("root@slave7",StrCmd)
	}else if BlockNumber==4400010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 4400001 --hzystail 4600000 >log"
		fmt.Println("On root@slave8 With " + StrCmd)
		go runCmd("root@slave8",StrCmd)
	}else if BlockNumber==4600010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 4600001 --hzystail 4800000 >log"
		fmt.Println("On root@slave9 With " + StrCmd)
		go runCmd("root@slave9",StrCmd)
	}else if BlockNumber==4800010{
		StrCmd := "/root/geth --datadir data103 --syncmode fast --hzyshead 4800001 --hzystail 5000000 >log"
		fmt.Println("On root@slave10 With " + StrCmd)
		go runCmd("root@slave10",StrCmd)
	}
}
//add end