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
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"

	"encoding/hex"
	"os"
	"strconv"
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
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}

	//add new by hzy 20-3-6
	// finish the full sync and for last slave
	//xing add 22-1-7
	if block.Number().Int64() == int64(common.GlobalEndHeight+1) && int64(common.GlobalEndHeight) != 0 {
		ExitFunc(block.Number().Int64() - 1)
	}
	if block.Number().Int64()%200000 == 0 {
		fmt.Println("block.Number().Int64()/200000", time.Now())
	}
	// if block.Number().Int64() == int64(3800001) {
	// 	os.Exit(0)
	// }
	//add end
	//add new by hzy 20-5-4
	//to count the index of transaction in the block
	common.VarOutTxInfo.TxIndex = 0
	//add end
	//add new by hzy 20-5-14
	//To initial the addr record array
	common.EoaAddrList = make(map[common.Address]bool, 50000)
	common.ContractAddrList = make(map[common.Address]bool, 50000)
	//add end
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		//add new by hzy 20-5-3
		//set out transactions info
		common.VarOutTxInfo.TxIndex += 1
		common.VarOutTxInfo.TxHash = tx.Hash().Hex()
		common.VarOutTxInfo.BlockNumber = block.Number().String()
		common.VarOutTxInfo.BlockHash = block.Hash().Hex()
		//count InTx layer
		common.GlobalInTxSeq = 0
		common.GlobalInTxLayer = 0
		common.GlobalOpcodeCounter = 0
		//add end
		//add new by hzy 20-5-17
		//initial the opcode list
		common.GlobalExternalInfoArray = make([]string, 0, 50000)
		//OutofGasList
		common.GlobalOutOfGasInfoArray = make([]string, 0, 5000)
		//the list of create contract addr
		common.GlobalContractAddrArray = make([]common.Address, 0, 10000)
		common.GlobalCallContractAddrArray = make([]common.Address, 0, 10000)

		receipt, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)

		//add new by hzy 20-5-11
		//To process the Log and token transfer info
		SetAndSendLogWithTokenTransInfoFunc(receipt.Logs, block.Time())
		SendTraceInfo(common.VarOutTxInfo.TxHash, common.VarOutTxInfo.ToAddress) //SendTraceInfo
		SendContractInfo(statedb)                                                //To record Contract Info
		SendCallContractBytecode(statedb)
		//add end
		//add new by hzy 20-5-4
		common.GlobalChOutTxInfo <- common.VarOutTxInfo
		//add end
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	//add new by hzy 20-5-14
	//To initial the addr record array
	ProcessEoaAddr(statedb)
	UpdateContractBalance(statedb)
	//add end

	// add new by hzy 20-5-4
	// when reach the tx numbers exist
	/*	if common.GlobalTotalTxsNum>=121186124{
		ExitFunc(block.Number().Int64())
	}*/
	// add end

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

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

//add new by hzy 20-5-7
//set the log info
func SetAndSendLogWithTokenTransInfoFunc(Logs []*types.Log, TimeStamp uint64) {
	var structLogsData common.StructLogsInfo
	var structTokenTxsData common.StructTokenTransferInfo
	var TokenTransferIndex int = 0 //the index that log is token transfer event
	for _, Log := range Logs {
		structLogsData.SzBlockHash = Log.BlockHash.Hex()
		structLogsData.SzBlockLogIndex = strconv.FormatUint(uint64(Log.Index), 10)
		structLogsData.SzBlockNumber = strconv.FormatUint(Log.BlockNumber, 10)
		structLogsData.SzBlockTimeStamp = strconv.FormatUint(TimeStamp, 10)
		structLogsData.SzTxHash = Log.TxHash.Hex()
		structLogsData.SzTxIndex = strconv.FormatUint(uint64(Log.TxIndex), 10)
		structLogsData.SzOriginatedAddress = Log.Address.Hex()
		structLogsData.SzData = hex.EncodeToString(Log.Data)
		if len(Log.Topics) != 0 { //use buffer to get effective
			var buffer bytes.Buffer
			buffer.WriteString(Log.Topics[0].Hex()) //traverse the topic array
			for _, topic := range Log.Topics[1:] {
				buffer.WriteString(" " + topic.Hex())
			}
			structLogsData.SzTopics = buffer.String()
		} else {
			structLogsData.SzTopics = ""
		}
		common.GlobalChLogInfo <- structLogsData

		//add new by hzy 20-5-10
		//To get token transfer and send it
		if len(Log.Topics) < 1 {
			continue
		}
		//the hash string means TRANSFER_EVENT_TOPIC occurs
		if Log.Topics[0].Hex() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" {
			TokenTransferIndex += 1
			HexSz2DecSz := func(data string) string {
				n, _ := strconv.ParseInt(data, 16, 64) //byte hex array to int64 dec
				IntSz := strconv.FormatInt(n, 10)      //int64 dex to string
				return IntSz
			}
			if len(Log.Topics) == 3 {
				structTokenTxsData.SzFromAddr = Log.Topics[1].Hex()
				structTokenTxsData.SzToAddr = Log.Topics[2].Hex()
				structTokenTxsData.SzValue = HexSz2DecSz(hex.EncodeToString(Log.Data))
			} else if len(Log.Topics) == 1 { //sometimes the  addr and balance all in log.data
				var SzLogData = hex.EncodeToString(Log.Data)
				if len(SzLogData) != 192 {
					log.Error("Unstandard Token Transfer Error", Log.TxHash.Hex())
					continue
				}
				//fmt.Println(SzLogData)
				structTokenTxsData.SzFromAddr = "0x" + SzLogData[:64]
				structTokenTxsData.SzToAddr = "0x" + SzLogData[64:128]
				structTokenTxsData.SzValue = HexSz2DecSz(SzLogData[128:])
			} else {
				log.Warn("HzysDebugInfo", "Unstandard Token Transfer Error", Log.TxHash.Hex())
				continue
			}
			structTokenTxsData.SzTokenAddr = Log.Address.Hex()
			structTokenTxsData.SzTxHash = Log.TxHash.Hex()
			structTokenTxsData.SzLogIndex = strconv.Itoa(TokenTransferIndex) //the index in tx
			structTokenTxsData.SzBlockTimeStamp = strconv.FormatUint(TimeStamp, 10)
			structTokenTxsData.SzBlockNumber = strconv.FormatUint(Log.BlockNumber, 10)
			structTokenTxsData.SzBlockHash = Log.BlockHash.Hex()
			common.GlobalChTokenTransInfo <- structTokenTxsData
		}
		//add end
	}
}

//add end

//add new by hzy 20-5-1
// exit print time and block
func ExitFunc(blockNumber int64) {
	log.Info("hzysDebugInfo", "Complete full sync and the End Height =", blockNumber)
	fmt.Println("End Height:", blockNumber)
	close(common.GlobalChBlockInfo)
	close(common.GlobalChOutTxInfo)
	close(common.GlobalChLogInfo)
	close(common.GlobalChInTxInfo)
	close(common.GlobalChTokenTransInfo)
	close(common.GlobalChContractInfo)
	close(common.GlobalChEoaInfo)
	close(common.GlobalChTraceInfo)
	close(common.GlobalUpdateContractBalanceInfo)
	close(common.GlobalChCallContractInfo)
	common.GlobalSyncWg.Wait() //wait all goroutine exits
	fmt.Println("hzysdebuginfo:", "GlobalSyncWg finish")
	common.PreInsertWg.Wait()
	fmt.Println("hzysdebuginfo:", "PreInsertWg finish")
	//add by hzy
	//To report the time
	fmt.Println("EOA update times:", common.TempNum)
	fmt.Printf("Start Time %d:%d:%d\n", common.StartTime.Hour(), common.StartTime.Minute(), common.StartTime.Second())
	t := time.Now()
	fmt.Printf("End Time %d:%d:%d\n", t.Hour(), t.Minute(), t.Second())
	var ExecTime = (time.Now().UnixNano() - common.InitialGethTime)
	fmt.Println("Total Time:", (ExecTime/1e9)/60, "mins  ", ExecTime/1e9, "s")
	//add end
	os.Exit(0)
}

//add end

//add new by hzy 20-5-14

//to process eoaAddrinfo
func ProcessEoaAddr(statedb *state.StateDB) {
	var structEoaInfo common.StructEoaInfo
	for addr, _ := range common.EoaAddrList {
		common.TempNum += 1
		structEoaInfo.Balance = statedb.GetBalance(addr).String()
		structEoaInfo.TimeStamp = common.VarOutTxInfo.TxHash //xing add new
		structEoaInfo.Address = strings.ToLower(addr.Hex())
		structEoaInfo.Nonce = strconv.FormatUint(statedb.GetNonce(addr), 10) //add new by xing 20-5-13
		common.GlobalChEoaInfo <- structEoaInfo
	}
}

//to update the contract balance
func UpdateContractBalance(statedb *state.StateDB) {
	var structContractInfo common.StructUpdateContractBalance
	for addr, _ := range common.ContractAddrList {
		structContractInfo.Balance = statedb.GetBalance(addr).String()
		structContractInfo.ContractAddr = strings.ToLower(addr.Hex())
		structContractInfo.Nonce = strconv.FormatUint(statedb.GetNonce(addr), 10) //add new by xing 20-5-13
		common.GlobalUpdateContractBalanceInfo <- structContractInfo
	}
}

//add end

//add new by hzy 20-5-18
func SendTraceInfo(ExternalTxHash string, ToAddress string) {
	if len(common.GlobalExternalInfoArray) > 1 {
		/*		if len(common.GlobalExternalInfoArray)==1&&common.GlobalExternalInfoArray[0]=="CALL##0"{
				return
			}*/
		var TraceInfo common.StructTraceInfo
		var buffer bytes.Buffer
		buffer.WriteString(common.GlobalExternalInfoArray[0])
		for _, trace := range common.GlobalExternalInfoArray[1:] {
			buffer.WriteString(" " + trace)
		}
		TraceInfo.SzExternalTxHash = ExternalTxHash
		TraceInfo.SzTraces = buffer.String()
		TraceInfo.SzToAddress = ToAddress
		//Set out of gas info
		if len(common.GlobalOutOfGasInfoArray) > 0 {
			var bufferForOutOfGas bytes.Buffer
			bufferForOutOfGas.WriteString(common.GlobalOutOfGasInfoArray[0])
			for _, trace := range common.GlobalOutOfGasInfoArray[1:] {
				bufferForOutOfGas.WriteString(" " + trace)
			}
			TraceInfo.SzOutOfGasTrace = bufferForOutOfGas.String()
		} else { //No out of gas info collect
			TraceInfo.SzOutOfGasTrace = ""
		}
		common.GlobalChTraceInfo <- TraceInfo
	}
}

//add end

//add new by hzy 20-9-15
//for add contract info
func getop(i int, opcode_value_list []string) string {
	op := strings.Split(opcode_value_list[i], "#")[0]
	return op
}
func getvalue(i int, opcode_value_list []string) string {
	value := strings.Split(opcode_value_list[i], "#")[1]
	return value
}

func GetOpVaLueList(str_bytecode string) []string {
	//str_bytecode := hex.EncodeToString(runtime_bytecode)
	len_bytecode := len(str_bytecode)
	//把所有的bytecode走一遍，生成操作码与操作值对应关系
	var opcode_value_list []string //存放opcode与其对应的value
	x := 0                         //记录移动位置
	for x < len_bytecode {
		str_current_opcode := str_bytecode[x : x+2]
		ret, _ := regexp.MatchString("^[6-7]?[0-9a-fA-F]$", str_current_opcode)
		if ret { //60~7f
			n, _ := strconv.ParseUint(str_current_opcode, 16, 32)
			var len_value uint64
			len_value = (n - 95) * 2 //记录value的长度
			var current_value string
			var current_op_value string
			if (x + 2 + int(len_value)) < len_bytecode {
				current_value = str_bytecode[x+2 : x+2+int(len_value)]
				current_op_value = str_current_opcode + "#" + current_value
			} else {
				//current_value = str_current_opcode[x+2 : ]
				current_op_value = str_current_opcode + "#"
			}
			opcode_value_list = append(opcode_value_list, current_op_value)
			x = x + 2 + int(len_value)
		} else {
			current_op_value := str_current_opcode + "#0"
			opcode_value_list = append(opcode_value_list, current_op_value)
			x = x + 2
		}
	}
	return opcode_value_list
}

func GetMethodId(opcode_value_list []string) []string {
	//parsh the function hash from opcode_value_list
	var methodid_list []string
	//jump_table_dict = {}  # 存放函数跳转表
	len_opcode_value := len(opcode_value_list)
	for i := 0; i < len_opcode_value; i++ {
		if getop(i, opcode_value_list) == "80" { //DUP1
			if ((i + 1) < len_opcode_value) && (getop(i+1, opcode_value_list) == "62" || getop(i+1, opcode_value_list) == "63") { //PUSH3, PUSH4
				if ((i + 2) < len_opcode_value) && getop(i+2, opcode_value_list) == "14" { //EQ
					ret, _ := regexp.MatchString("^[6-7]?[0-9a-fA-F]$", getop(i+3, opcode_value_list))
					if ((i + 3) < len_opcode_value) && ret { //PUSHx
						//if ((i+4)<len_opcode_value) && (getop(i+4) == "56" || getop(i+4) == "57"){//JUMP,JUMPI
						methodid := getvalue(i+1, opcode_value_list)
						methodid_list = append(methodid_list, methodid)
					}
				}
			}
		} else if getop(i, opcode_value_list) == "62" || getop(i, opcode_value_list) == "63" { //PUSH3,PUSH4
			if ((i + 1) < len_opcode_value) && getop(i+1, opcode_value_list) == "81" { //DUP2
				if ((i + 2) < len_opcode_value) && getop(i+2, opcode_value_list) == "14" { //EQ
					ret, _ := regexp.MatchString("^[6-7]?[0-9a-fA-F]$", getop(i+3, opcode_value_list))
					if ((i + 3) < len_opcode_value) && ret { //PUSHx
						//if ((i+4)<len_opcode_value) && (getop(i+4) == "56" || getop(i+4) == "57"){//JUMP,JUMPI
						methodid := getvalue(i, opcode_value_list)
						methodid_list = append(methodid_list, methodid)
					}
				}
			}
		} else {
		}
	}
	return methodid_list
}

func HasEventTransfer(opcode_value_list []string) bool {
	for _, value := range opcode_value_list {
		ret, _ := regexp.MatchString("^7f#.*", value)
		if ret {
			opvalue := strings.Split(value, "#")[1]
			if opvalue == "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" {
				return true
			}
		}
	}
	return false
}
func IsERC20(opcode_value_list []string, methodid_list []string) string {
	num := 0
	tag := false
	for _, value := range methodid_list {
		if value == "70a08231" { //balanceOf()
			tag = true
		} else if value == "a9059cbb" { //transfer()
			num += 1
		} else if value == "23b872dd" { //transferFrom
			num += 1
		} else {
		}
	}
	//判断是否含有标准事件且两个功能函数
	if num >= 1 && tag == true && HasEventTransfer(opcode_value_list) {
		return "1"
	} else {
		return "0"
	}
}

func IsERC721(opcode_value_list []string, methodid_list []string, isErc20 bool) bool {
	num := 0
	if isErc20 {
		for _, value := range methodid_list {
			if value == "42842e0e" || value == "b88d4fde" { //safeTransferFrom
				num += 1
			}
		}
		if num >= 1 {
			return true
		}
	}
	return false
}

//add end

//add new by hzy 20-5-14
//to let the type of MethodIDs became stirng
func StringArray2String(MethodIDs []string) string {
	var MethodIDSlength = len(MethodIDs)
	if MethodIDSlength == 0 {
		return ""
	} else if MethodIDSlength == 1 {
		return MethodIDs[0]
	}

	var buffer bytes.Buffer
	buffer.WriteString(MethodIDs[0])
	for _, MethodID := range MethodIDs[1:] {
		buffer.WriteString(" " + MethodID)
	}
	return buffer.String()
}

//add new by hzy 20-5-31

func SetContractInfo(statedb *state.StateDB, addr common.Address) {
	ret := statedb.GetCode(addr)
	if len(ret) != 0 { //if the length is zero, it must be reverted.
		var ContractInfo common.StructContractInfo
		ContractInfo.Bytecode = hex.EncodeToString(ret)
		opcode_value_list := GetOpVaLueList(ContractInfo.Bytecode)
		MethodIds := GetMethodId(opcode_value_list)
		ContractInfo.MethodId = StringArray2String(MethodIds)
		ContractInfo.IsERC20 = IsERC20(opcode_value_list, MethodIds)
		//add new by xing 20-5-31
		ContractInfo.Nonce = strconv.FormatUint(statedb.GetNonce(addr), 10)
		//add end
		ContractInfo.BlockNumber = common.VarOutTxInfo.BlockNumber
		ContractInfo.BlockHash = common.VarOutTxInfo.BlockHash
		ContractInfo.BlockTimeStamp = common.VarOutTxInfo.TimeStamp
		ContractInfo.Address = strings.ToLower(addr.Hex())
		ContractInfo.Balance = statedb.GetBalance(addr).String()
		common.GlobalContractInsertedFlag[addr.Hex()] = struct{}{}
		common.GlobalChContractInfo <- ContractInfo
	}
}

func SendContractInfo(statedb *state.StateDB) {
	for _, addr := range common.GlobalContractAddrArray {
		SetContractInfo(statedb, addr)
	}
}

//add new by hzy on 20-12-27
func SendCallContractBytecode(statedb *state.StateDB) {
	for _, addr := range common.GlobalCallContractAddrArray {
		if _, ok := common.GlobalContractInsertedFlag[addr.Hex()]; !ok {
			SetCallContractBytecode(statedb, addr)
		}
	}
}

//add end

func SetCallContractBytecode(statedb *state.StateDB, addr common.Address) {
	ret := statedb.GetCode(addr)
	if len(ret) != 0 { //if the length is zero, it must be reverted.
		var CallContractInfo common.StructCallContractInfo
		CallContractInfo.Address = addr.Hex()
		CallContractInfo.Bytecode = hex.EncodeToString(ret)
		common.GlobalContractInsertedFlag[addr.Hex()] = struct{}{}
		common.GlobalChCallContractInfo <- CallContractInfo
	}
}

//add end
