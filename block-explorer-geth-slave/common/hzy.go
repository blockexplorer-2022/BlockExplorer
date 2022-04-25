package common

import (
	"sync"
	"time"

	"github.com/tsuna/gohbase"
)

// add new by hzy 3-5
// these two vars specify the sync start height and end height
var GlobalStartHeight int
var GlobalEndHeight int

// add end
//xing add 22-1-7
var DataBaseName string
var Server string
var User string
var Pass string

//add new by hzy 3-6
// to record the ReSyncCnt
var ReSyncCnt int
var CheckPoint int

// add end

//Add new by hzy 20-3-6
//To transform sql exec
var GlobalOpcodeSeqs []string

//add end

//add new by hzy 20-3-12
//to record running time
var StartTime time.Time
var InitialGethTime int64
var TotalDBTime int64

//var ChSyncDone chan struct{}
// add end

//add new by hzy 20-3-18
//to record flag state
var PeerSyncflag bool
var PeerResetFlag chan bool //define a bool type varible
var ResetOriginalFlag bool

//add end

//add new by hzy 20-4-23
//to get the global fb
var GlobalClient gohbase.Client

//add end

//add new by hzy 20-4-29
//to get the counter of Numbers of Txs
var GlobalTotalTxsNum int

//add end

//add new by hzy 20-5-1
//add the information of block
type StructBlockInfo struct {
	StrTimeStamp        string //The timestamp for when the block was collated
	StrBlockNumber      string //The block number
	StrBlockHash        string //Hash of the block
	StrBlockParentHash  string //Hash of the parent block
	StrNonce            string //Hash of the generated proof-of-work
	StrUncleHash        string //SHA3 of the uncles data in the block
	StrLogsBloom        string //The bloom filter for the logs of the block
	StrTransactionsRoot string //The root of the transaction trie of the block
	StrStateRoot        string //The root of the final state trie of the block
	StrReceiptRoot      string //The root of the receipts trie of the block
	StrMiner            string //The address of the beneficiary to whom the mining rewards were given
	StrDifficulty       string //Integer of the difficulty for this block
	StrTotalDifficulty  string //Integer of the total difficulty of the chain until this block
	StrSize             string //The size of this block in bytes
	StrExtraData        string //The extra data field of this block
	StrGasLimit         string //The maximum gas allowed in this block
	StrGasUsed          string //The total used gas by all transactions in this block
	StrTransNums        string //The number of transactions in the block
}

//add end

//add new by hzy 20-5-3
//to record External transaction info

type StructOutTxInfo struct {
	//set at core/state_process.go
	TxHash      string
	BlockNumber string
	BlockHash   string
	//set at core/state_transition.go
	TimeStamp   string
	TxIndex     int
	Tag         string
	FromAddress string
	ToAddress   string
	Value       string
	GasLimit    string
	GasUsed     string
	GasPrice    string
	InputData   string
	Nonce       string
	//ReceiptContractAddress string //if exist, or null
	ToType   string
	FromType string
	//ReceiptRoot   string
	TxStatus bool
}

var VarOutTxInfo StructOutTxInfo

//add end

//add by hzy 20-5-7
//add for Log info
type StructLogsInfo struct {
	SzBlockLogIndex     string //the log index in block
	SzBlockTimeStamp    string
	SzBlockNumber       string
	SzBlockHash         string
	SzTxHash            string
	SzTxIndex           string //the log index in Tx
	SzOriginatedAddress string //the trigger of this event
	SzData              string //
	SzTopics            string //Topics joint by ##
}

//add end

//add by hzy 20-5-31
//to record Internal transactions information
type StructInTxInfo struct {
	TxCallSeq    string
	TxLayer      string
	TxHash       string
	FromAddress  string
	ToAddress    string
	InputData    string //the inputdata of create is the deployment code
	Value        string
	Tag          string
	FromType     string
	ToType       string //the toadddr of callcode and delegatecall shoud be caller but not correct
	IntrinsicGas string
	GasUsed      string //check the gasused of callcode, delegatecall
	Errors       string // 0 means successful 1,2,3 has their explanition
}

var GlobalInTxLayer int
var GlobalInTxSeq int

//add end

//add new by hzy 20-5-10
//To record the token transfer info
type StructTokenTransferInfo struct {
	SzTokenAddr      string
	SzFromAddr       string
	SzToAddr         string
	SzValue          string
	SzTxHash         string
	SzLogIndex       string //the log in this externalTx
	SzBlockTimeStamp string
	SzBlockNumber    string
	SzBlockHash      string
}

//add end

//add new by hzy 20-5-11
//to record EOA information
type StructEoaInfo struct {
	Address string
	TimeStamp string
	Balance string
	//add new by xing 20-5-31
	Nonce string
}

var VarEoaInfo StructEoaInfo

type StructContractInfo struct {
	//add contract address when creating the contract
	Address string
	//get contract balance from the evm state when transaction excuting. need to update
	Balance string
	//add contract bytecode at vm/evm.go
	Bytecode string
	//parse contract signatures from bytecode
	MethodId string
	//add at state_transition.go
	BlockTimeStamp string
	BlockNumber    string
	BlockHash      string
	//model the erc20 and erc721 pattern
	IsERC20 string
	//IsERC721       bool
	//
	//SendTxNum   int
	//RecvTxNum   int
	//
	//InTxs       []string
	//OutTxs    	[]string
	//add new by xing 20-5-31
	Nonce string
	//add end
}

//add new by hzy in 20-12-27
//To get the bytecode
type StructCallContractInfo struct {
	Address  string
	Bytecode string
}

//add end

var GlobalContractAddrArray []Address //To record the Contract
var GlobalCallContractAddrArray []Address

//add end

//add new by hzy 20-5-4
var EoaAddrList map[Address]bool
var ContractAddrList map[Address]bool

//add end

//add new by hzy 20-5-4
//multi thread var
var GlobalSyncWg sync.WaitGroup
var PreInsertWg sync.WaitGroup
var GlobalChBlockInfo chan StructBlockInfo
var GlobalChOutTxInfo chan StructOutTxInfo
var GlobalChInTxInfo chan StructInTxInfo
var GlobalChLogInfo chan StructLogsInfo
var GlobalChTokenTransInfo chan StructTokenTransferInfo
var GlobalChContractInfo chan StructContractInfo
var GlobalChEoaInfo chan StructEoaInfo
var GlobalChTraceInfo chan StructTraceInfo
var GlobalUpdateContractBalanceInfo chan StructUpdateContractBalance
var GlobalChCallContractInfo chan StructCallContractInfo

//add end

//add new by hzy 20-5-15
//to identify the balance in eoa and contract
var SlaveId string

//add end

//add new bu hzy 20-5-17
//To record external Info
type StructTraceInfo struct {
	SzExternalTxHash string
	SzTraces         string
	SzToAddress      string
	SzOutOfGasTrace  string
}

var GlobalExternalInfoArray []string
var GlobalOutOfGasInfoArray []string

//add end

type StructUpdateContractBalance struct {
	ContractAddr string
	Balance      string
	Nonce        string
}

//add new by hzy 20-6-3
//To solve the gas compute problem in replay
var GlobalOpcodeCounter int

//add end

//add new by hzy 20-6-7
//the execute whether it enter the call execute the bytecode
var GlobalCallInFlag bool

//add end

//add new by hzy 20-11-8
var TempNum int

//add end

//To spcify the addr has been inserted in db
var GlobalContractInsertedFlag map[string]struct{}
