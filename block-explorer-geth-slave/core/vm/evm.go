// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	//add end
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if p := precompiles[*contract.CodeAddr]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input, readOnly)
		}
	}
	return nil, ErrNoCompatibleInterpreter
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreters []Interpreter
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64

	//add new by zhy 20-4-30
	//add the flag of tx start
	isTxStart bool
	//add end
}

func (evm *EVM) IsTxStart() bool      { return evm.isTxStart }
func (evm *EVM) SetTxStart(flag bool) { evm.isTxStart = flag }

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		interpreters: make([]Interpreter, 0, 1),
	}

	if chainConfig.IsEWASM(ctx.BlockNumber) {
		// to be implemented by EVM-C and Wagon PRs.
		// if vmConfig.EWASMInterpreter != "" {
		//  extIntOpts := strings.Split(vmConfig.EWASMInterpreter, ":")
		//  path := extIntOpts[0]
		//  options := []string{}
		//  if len(extIntOpts) > 1 {
		//    options = extIntOpts[1..]
		//  }
		//  evm.interpreters = append(evm.interpreters, NewEVMVCInterpreter(evm, vmConfig, options))
		// } else {
		// 	evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm, vmConfig))
		// }
		panic("No supported ewasm interpreter yet.")
	}

	// vmConfig.EVMInterpreter will be used by EVM-C, it won't be checked here
	// as we always want to have the built-in EVM as the failover option.
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]

	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Cancelled returns true if Cancel has been called
func (evm *EVM) Cancelled() bool {
	return atomic.LoadInt32(&evm.abort) == 1
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	//add new by hzy 20-5-331
	var CurrentIndex int
	var CallPosInList int
	var InTxInfo common.StructInTxInfo
	if evm.isTxStart {
		common.GlobalInTxSeq += 1
		CurrentIndex = common.GlobalInTxSeq
		common.GlobalInTxLayer += 1                 //get the value before return
		defer func() { common.GlobalInTxLayer-- }() //balance the call and return
		if common.GlobalInTxSeq > 1 {
			InTxInfo = evm.SetInTxInfoPartly(caller, addr, input, gas, value.String(),
				common.GlobalInTxSeq, common.GlobalInTxLayer, "CALL")
			defer func() {
				//Set the Call trace
				if common.GlobalCallInFlag { //enter the evm
					RecoverExternalInfoForCALL("CALL", "1#"+InTxInfo.Errors, CallPosInList) //"1" Enter the call
				} else {
					RecoverExternalInfoForCALL("CALL", "0#"+InTxInfo.Errors, CallPosInList)
				}
				common.GlobalChInTxInfo <- InTxInfo
			}()
		}
		common.GlobalCallInFlag = false                     //whether this call will execute the bytecode
		CallPosInList = GetExternalInfoForCALL("CALL", "0") //assume it not
	}
	SetGasandErr := func(GasUsed string, ErrType string) { //hzy add this func to process some info
		if evm.isTxStart && common.GlobalInTxSeq > 1 {
			InTxInfo.GasUsed = GasUsed //no gas use
			InTxInfo.Errors = ErrType  //index of this error in call
		}
	}
	//add end

	if evm.vmConfig.NoRecursion && evm.depth > 0 { //error type 1
		SetGasandErr("0", "1")
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) { //error type 2
		SetGasandErr("0", "2")
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		SetGasandErr("0", "3")
		return nil, gas, ErrInsufficientBalance
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if precompiles[addr] == nil && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			}
			SetGasandErr("0", "4")
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)

	//add new by hzy 20-5-11
	if evm.isTxStart {
		SetAccountInfo(evm, caller.Address())
		SetAccountInfo(evm, addr)
	}
	//add end

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// Even if the account has no code, we need to continue because it might be a precompile
	start := time.Now()
	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	}
	/*	if common.VarOutTxInfo.TxHash=="0xac1c0c97a2933fc59cab05d392cbb0eec5d3d3d986d8c10dbeb5aa599784fa11"&&
			evm.isTxStart {
		    fmt.Println(evm.depth,addr.Hex(),len(contract.Code),contract.CodeHash.Hex())
		}*/
	ret, err = run(evm, contract, input, false)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	//add new by hzy 20-6-6,collect call contract addr
	if evm.isTxStart && len(contract.Code) != 0 {
		evm.ContractCallAddrCollect(addr)
	}

	//add new by hzy 20-6-1
	//count the number of txs
	if evm.isTxStart && CurrentIndex > 1 {
		UInt64GasUsed := gas - contract.Gas
		if err == nil {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "0")
		} else if err == errExecutionReverted {
			SetGasandErr("0", "6") //this error on gas used.
		} else {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "5")
		}
	}
	//add end

	return ret, contract.Gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	//add new by hzy 20-5-5
	var CurrentIndex int
	var CallPosInList int
	var InTxInfo common.StructInTxInfo
	if evm.isTxStart {
		common.GlobalInTxSeq += 1
		CurrentIndex = common.GlobalInTxSeq
		common.GlobalInTxLayer += 1
		defer func() { common.GlobalInTxLayer-- }() //balance the call and return
		if common.GlobalInTxSeq > 1 {
			InTxInfo = evm.SetInTxInfoPartly(caller, addr, input, gas, value.String(), common.GlobalInTxSeq, common.GlobalInTxLayer, "CallCode")
			defer func() {
				if common.GlobalCallInFlag { //enter the evm
					RecoverExternalInfoForCALL("CALLCODE", "1#"+InTxInfo.Errors, CallPosInList) //"1" Enter the call
				} else {
					RecoverExternalInfoForCALL("CALLCODE", "0#"+InTxInfo.Errors, CallPosInList)
				}
				common.GlobalChInTxInfo <- InTxInfo

			}()
		}
		common.GlobalCallInFlag = false //whether this call will execute the bytecode
		CallPosInList = GetExternalInfoForCALL("CALLCODE", "0")
	}
	SetGasandErr := func(GasUsed string, ErrType string) { //hzy add this func to process some info
		if evm.isTxStart && common.GlobalInTxSeq > 1 {
			InTxInfo.GasUsed = GasUsed //no gas use
			InTxInfo.Errors = ErrType  //index of this error in call
		}
	}
	//add end
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		SetGasandErr("0", "1")
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		SetGasandErr("0", "2")
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		SetGasandErr("0", "3")
		return nil, gas, ErrInsufficientBalance
	}
	//add new by hzy 20-5-11
	if evm.isTxStart {
		SetAccountInfo(evm, caller.Address())
		SetAccountInfo(evm, addr)
	}
	//add end
	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
	//add new by hzy 20-6-7

	ret, err = run(evm, contract, input, false)
	//add new by hzy in 20-6-7
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	//add new by hzy 20-6-6,collect call contract addr
	if evm.isTxStart && len(contract.Code) != 0 {
		evm.ContractCallAddrCollect(addr)
	}

	//add new by hzy 20-6-1
	//count the number of txs
	if evm.isTxStart && CurrentIndex > 1 {
		UInt64GasUsed := gas - contract.Gas
		if err == nil {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "0")
		} else if err == errExecutionReverted {
			SetGasandErr("0", "6") //this error on gas used.
		} else {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "5")
		}
	}
	//add end

	return ret, contract.Gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	//add new by hzy 20-5-31
	var CurrentIndex int
	var CallPosInList int
	var InTxInfo common.StructInTxInfo
	if evm.isTxStart {
		common.GlobalInTxSeq += 1
		CurrentIndex = common.GlobalInTxSeq
		common.GlobalInTxLayer += 1
		defer func() { common.GlobalInTxLayer-- }() //balance the call and return
		if common.GlobalInTxSeq > 1 {
			InTxInfo = evm.SetInTxInfoPartly(caller, addr, input, gas, "0", common.GlobalInTxSeq, common.GlobalInTxLayer, "DelegateCall")
			defer func() { //finaly execute
				if common.GlobalCallInFlag { //enter the evm
					RecoverExternalInfoForCALL("DELEGATECALL", "1#"+InTxInfo.Errors, CallPosInList) //"1" Enter the call
				} else {
					RecoverExternalInfoForCALL("DELEGATECALL", "0#"+InTxInfo.Errors, CallPosInList)
				}
				common.GlobalChInTxInfo <- InTxInfo //insert To hbase
			}()
		}
		common.GlobalCallInFlag = false //whether this call will execute the bytecode
		CallPosInList = GetExternalInfoForCALL("DELEGATECALL", "0")
	}
	SetGasandErr := func(GasUsed string, ErrType string) { //hzy add this func to process some info
		if evm.isTxStart && common.GlobalInTxSeq > 1 {
			InTxInfo.GasUsed = GasUsed //no gas use
			InTxInfo.Errors = ErrType  //index of this error in call
		}
	}
	//add end
	//add new by hzy 20-5-11
	if evm.isTxStart {
		SetAccountInfo(evm, caller.Address())
		SetAccountInfo(evm, addr)
	}
	//add end
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		SetGasandErr("0", "1")
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		SetGasandErr("0", "2")
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, false)

	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	//add new by hzy 20-6-6,collect call contract addr
	if evm.isTxStart && len(contract.Code) != 0 {
		evm.ContractCallAddrCollect(addr)
	}

	//add new by hzy 20-6-1
	//count the number of txs
	if evm.isTxStart && CurrentIndex > 1 {
		UInt64GasUsed := gas - contract.Gas
		if err == nil {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "0")
		} else if err == errExecutionReverted {
			SetGasandErr("0", "6") //this error on gas used.
		} else {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "5")
		}
	}
	//add end
	return ret, contract.Gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	//add new by hzy 20-6-1
	var CallPosInList int
	var CurrentIndex int
	var InTxInfo common.StructInTxInfo
	if evm.isTxStart {
		common.GlobalInTxSeq += 1
		CurrentIndex = common.GlobalInTxSeq
		common.GlobalInTxLayer += 1
		defer func() { common.GlobalInTxLayer-- }()
		if common.GlobalInTxSeq > 1 {
			InTxInfo = evm.SetInTxInfoPartly(caller, addr, input, gas, "0", common.GlobalInTxSeq,
				common.GlobalInTxLayer, "StaticCall")
			defer func() {
				if common.GlobalCallInFlag { //enter the evm
					RecoverExternalInfoForCALL("STATICCALL", "1#"+InTxInfo.Errors, CallPosInList) //"1" Enter the call
				} else {
					RecoverExternalInfoForCALL("STATICCALL", "0#"+InTxInfo.Errors, CallPosInList)
				}
				common.GlobalChInTxInfo <- InTxInfo
			}()
		}
		common.GlobalCallInFlag = false //whether this call will execute the bytecode
		CallPosInList = GetExternalInfoForCALL("STATICCALL", "0")
	}
	SetGasandErr := func(GasUsed string, ErrType string) { //hzy add this func to process some info
		if evm.isTxStart && common.GlobalInTxSeq > 1 {
			InTxInfo.GasUsed = GasUsed //no gas use
			InTxInfo.Errors = ErrType  //index of this error in call
		}
	}
	//add end
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		SetGasandErr("0", "1")
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		SetGasandErr("0", "2")
		return nil, gas, ErrDepth
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, bigZero)

	//add new by hzy 20-5-11
	if evm.isTxStart {
		SetAccountInfo(evm, caller.Address())
		SetAccountInfo(evm, addr)
	}
	//add end

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = run(evm, contract, input, true)

	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	//add new by hzy 20-6-6,collect call contract addr
	if evm.isTxStart && len(contract.Code) != 0 {
		evm.ContractCallAddrCollect(addr)
	}

	//add new by hzy 20-6-1
	//count the number of txs
	if evm.isTxStart && CurrentIndex > 1 {
		UInt64GasUsed := gas - contract.Gas
		if err == nil {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "0")
		} else if err == errExecutionReverted {
			SetGasandErr("0", "6") //this error on gas used.
		} else {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "5")
		}
	}
	//add end
	//add new by hzy in 20-6-7
	defer func() { //ensure can get all the errors
		if evm.isTxStart {

		}
	}()
	// add end
	return ret, contract.Gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	//add new by hzy 20-5-5
	var CurrentIndex int // the record the current call seq
	var InTxInfo common.StructInTxInfo
	var CallPosInList int
	if evm.isTxStart {
		common.GlobalInTxSeq += 1
		CurrentIndex = common.GlobalInTxSeq
		common.GlobalInTxLayer += 1
		defer func() { common.GlobalInTxLayer-- }()
		if common.GlobalInTxSeq > 1 {
			InTxInfo = evm.SetInTxInfoForCreate(caller, codeAndHash, gas, value.String(), address, common.GlobalInTxSeq,
				common.GlobalInTxLayer)
			defer func() {
				if common.GlobalCallInFlag { //enter the evm
					RecoverExternalInfoForCALL("CREATE", "1#"+InTxInfo.Errors+"#"+address.Hex(), CallPosInList) //"1" Enter the call
				} else {
					RecoverExternalInfoForCALL("CREATE", "0#"+InTxInfo.Errors+"#"+address.Hex(), CallPosInList)
				}
				common.GlobalChInTxInfo <- InTxInfo
			}()
		}
		//add new by hzy 20-6-7
		//To get the geth whether go into call
		common.GlobalCallInFlag = false //whether this call will execute the bytecode
		CallPosInList = GetExternalInfoForCALL("CREATE", "0")
		//add end
	}
	//add new by hzy in 3030-6-1
	SetGasandErr := func(GasUsed string, ErrType string) { //hzy add this func to process some info
		if evm.isTxStart && common.GlobalInTxSeq > 1 {
			InTxInfo.GasUsed = GasUsed //no gas use
			InTxInfo.Errors = ErrType  //index of this error in call
		}
	}
	//add end
	if evm.depth > int(params.CallCreateDepth) {
		SetGasandErr("0", "2")
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		SetGasandErr("0", "3")
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		SetGasandErr("0", "9")
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Transfer(evm.StateDB, caller.Address(), address, value)

	//add new by hzy 20-5-11
	if evm.isTxStart {
		SetAccountInfo(evm, caller.Address())
	}
	//add end

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		SetGasandErr("0", "1")
		return nil, address, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, codeAndHash.code, gas, value)
	}
	start := time.Now()

	ret, err := run(evm, contract, nil, false)

	// check whether the max code size has been exceeded
	maxCodeSizeExceeded := evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
			/*if common.VarOutTxInfo.TxHash=="0xc999f8c308bef0c2e263ecedf3d041f88e2b16ee315d763b02a04235bf358714" {
			   fmt.Println("HzysDebugInfo:SetCode",address.Hex(),"Bytecode",hex.EncodeToString(ret))
			}*/
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}
	//add new by hzy 20-6-6,collect create contract addr
	evm.ContractCreateAddrCollect(address)
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	//add new by hzy 20-6-1
	//count the number of txs
	if evm.isTxStart && CurrentIndex > 1 {
		UInt64GasUsed := gas - contract.Gas
		if err == nil {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "0")
		} else if err == errExecutionReverted {
			SetGasandErr("0", "6") //this error on gas used.
		} else if err == errMaxCodeSizeExceeded {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "7")
		} else if err == ErrCodeStoreOutOfGas {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "8")
		} else {
			SetGasandErr(strconv.FormatUint(UInt64GasUsed, 10), "5")
		}
	}
	//add end
	return ret, address, contract.Gas, err

}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

//add new by hzy 20-5-5
func isEoa(evm *EVM, addr common.Address) bool {
	if evm.StateDB.GetCodeSize(addr) != 0 {
		return false
	} else {
		return true
	}
}

//add end

//add new by hzy 20-5-11
//set Eoa information
func SetAccountInfo(evm *EVM, addr common.Address) {
	if isEoa(evm, addr) {
		common.EoaAddrList[addr] = true
	} else {
		common.ContractAddrList[addr] = true
	}
}

//To Set part InTx Info.
func (evm *EVM) SetInTxInfoPartly(caller ContractRef, addr common.Address, input []byte, gas uint64, value string, CallSeq int, CallLayer int, Tag string) common.StructInTxInfo {
	var InTxInfo common.StructInTxInfo
	toaddr := AccountRef(addr)
	InTxInfo.TxCallSeq = strconv.Itoa(CallSeq)
	InTxInfo.TxLayer = strconv.Itoa(CallLayer)
	InTxInfo.FromType = "CONTRACT"
	InTxInfo.ToType = "UNKOWN TYPE"
	if isEoa(evm, toaddr.Address()) == true {
		InTxInfo.ToType = "EOA"
	} else {
		InTxInfo.ToType = "CONTRACT"
	}
	if len(input) == 0 {
		InTxInfo.InputData = "0x"
	} else {
		InTxInfo.InputData = hex.EncodeToString(input)
	}
	InTxInfo.ToAddress = strings.ToLower(toaddr.Address().Hex())
	InTxInfo.FromAddress = strings.ToLower(caller.Address().Hex())
	InTxInfo.Value = value
	InTxInfo.Tag = Tag
	InTxInfo.IntrinsicGas = strconv.FormatUint(gas, 10)
	InTxInfo.TxHash = common.VarOutTxInfo.TxHash
	return InTxInfo
}

//add end

func (evm *EVM) SetInTxInfoForCreate(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value string, address common.Address, CallSeq int, CallLayer int) common.StructInTxInfo {
	var InTxInfo common.StructInTxInfo
	InTxInfo.TxCallSeq = strconv.Itoa(CallSeq)
	InTxInfo.TxLayer = strconv.Itoa(CallLayer)
	InTxInfo.FromType = "CONTRACT"
	InTxInfo.ToType = "CONTRACT"
	InTxInfo.ToAddress = strings.ToLower(address.Hex())
	InTxInfo.FromAddress = strings.ToLower(caller.Address().Hex())
	InTxInfo.Value = value
	InTxInfo.Tag = "CREATE"
	InTxInfo.IntrinsicGas = strconv.FormatUint(gas, 10)
	Runtimecode := hex.EncodeToString(codeAndHash.code)
	if len(Runtimecode) == 0 {
		InTxInfo.InputData = "0x"
	} else {
		InTxInfo.InputData = Runtimecode
	}
	InTxInfo.TxHash = common.VarOutTxInfo.TxHash
	return InTxInfo
}

//add new by hzy 20-12-19,collect contract addr
func (evm *EVM) ContractCreateAddrCollect(ContractAddr common.Address) {
	if evm.isTxStart {
		common.GlobalContractAddrArray = append(common.GlobalContractAddrArray, ContractAddr) //to record the contract addr when create contract
	}
}

// add new by hzy 20-12-27,collect contract call bytecode
func (evm *EVM) ContractCallAddrCollect(ContractAddr common.Address) {
	if _, ok := common.GlobalContractInsertedFlag[ContractAddr.Hex()]; !ok {
		common.GlobalCallContractAddrArray = append(common.GlobalCallContractAddrArray, ContractAddr)
	}
}

//add new by hzy 20-6-7
//whether it enter the call
func GetExternalInfoForCALL(SzOpcode string, ExternalData string) int {
	common.GlobalExternalInfoArray = append(common.GlobalExternalInfoArray, SzOpcode+"##"+ExternalData)
	return len(common.GlobalExternalInfoArray) - 1
}

func RecoverExternalInfoForCALL(SzOpcode string, ExternalData string, pos int) {
	common.GlobalExternalInfoArray[pos] = SzOpcode + "##" + ExternalData
}

//add
