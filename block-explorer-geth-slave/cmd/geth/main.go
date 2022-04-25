// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// geth is the official command-line client for Ethereum.
package main

import (
	"fmt"
	"math"
	"os"
	"runtime"
	godebug "runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	//add new by hzy in 20-8-28
	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	//add end

	"github.com/elastic/gosigar"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/console"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/les"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	cli "gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "geth" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, gitDate, "the go-ethereum command line interface")

	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.AncientFlag,
		utils.KeyStoreDirFlag,
		utils.ExternalSignerFlag,
		utils.NoUSBFlag,
		utils.SmartCardDaemonPathFlag,
		utils.OverrideIstanbulFlag,
		utils.OverrideMuirGlacierFlag,
		utils.EthashCacheDirFlag,
		utils.EthashCachesInMemoryFlag,
		utils.EthashCachesOnDiskFlag,
		utils.EthashDatasetDirFlag,
		utils.EthashDatasetsInMemoryFlag,
		utils.EthashDatasetsOnDiskFlag,
		utils.TxPoolLocalsFlag,
		utils.TxPoolNoLocalsFlag,
		utils.TxPoolJournalFlag,
		utils.TxPoolRejournalFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.SyncModeFlag,
		utils.ExitWhenSyncedFlag,
		utils.GCModeFlag,
		utils.LightServeFlag,
		utils.LightLegacyServFlag,
		utils.LightIngressFlag,
		utils.LightEgressFlag,
		utils.LightMaxPeersFlag,
		utils.LightLegacyPeersFlag,
		utils.LightKDFFlag,
		utils.UltraLightServersFlag,
		utils.UltraLightFractionFlag,
		utils.UltraLightOnlyAnnounceFlag,
		utils.WhitelistFlag,
		utils.CacheFlag,
		utils.CacheDatabaseFlag,
		utils.CacheTrieFlag,
		utils.CacheGCFlag,
		utils.CacheNoPrefetchFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.MiningEnabledFlag,
		utils.MinerThreadsFlag,
		utils.MinerLegacyThreadsFlag,
		utils.MinerNotifyFlag,
		utils.MinerGasTargetFlag,
		utils.MinerLegacyGasTargetFlag,
		utils.MinerGasLimitFlag,
		utils.MinerGasPriceFlag,
		utils.MinerLegacyGasPriceFlag,
		utils.MinerEtherbaseFlag,
		utils.MinerLegacyEtherbaseFlag,
		utils.MinerExtraDataFlag,
		utils.MinerLegacyExtraDataFlag,
		utils.MinerRecommitIntervalFlag,
		utils.MinerNoVerfiyFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.TestnetFlag,
		utils.RinkebyFlag,
		utils.GoerliFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.EthStatsURLFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.EWASMInterpreterFlag,
		utils.EVMInterpreterFlag,
		configFileFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCCORSDomainFlag,
		utils.RPCVirtualHostsFlag,
		utils.GraphQLEnabledFlag,
		utils.GraphQLListenAddrFlag,
		utils.GraphQLPortFlag,
		utils.GraphQLCORSDomainFlag,
		utils.GraphQLVirtualHostsFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
		utils.InsecureUnlockAllowedFlag,
		utils.RPCGlobalGasCap,
	}

	whisperFlags = []cli.Flag{
		utils.WhisperEnabledFlag,
		utils.WhisperMaxMessageSizeFlag,
		utils.WhisperMinPOWFlag,
		utils.WhisperRestrictConnectionBetweenLightClientsFlag,
	}

	metricsFlags = []cli.Flag{
		utils.MetricsEnabledFlag,
		utils.MetricsEnabledExpensiveFlag,
		utils.MetricsEnableInfluxDBFlag,
		utils.MetricsInfluxDBEndpointFlag,
		utils.MetricsInfluxDBDatabaseFlag,
		utils.MetricsInfluxDBUsernameFlag,
		utils.MetricsInfluxDBPasswordFlag,
		utils.MetricsInfluxDBTagsFlag,
	}
)

func init() {
	// Initialize the CLI app and start Geth
	app.Action = geth
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2013-2019 The go-ethereum Authors"
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		importPreimagesCommand,
		exportPreimagesCommand,
		copydbCommand,
		removedbCommand,
		dumpCommand,
		inspectCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		makecacheCommand,
		makedagCommand,
		versionCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		// See retesteth.go
		retestethCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))
	//xing add 22-1-7
	// xingMagicFlags := []cli.Flag{
	// 	cli.StringFlag{
	// 		Name:        "database",                      // 命令名称
	// 		Usage:       "Database where store the data", // 命令说明
	// 		Value:       "XingTest",                      // 默认值
	// 		Destination: &(common.DataBaseName),          // 赋值
	// 	},
	// 	cli.StringFlag{
	// 		Name:        "server",                                                          // 命令名称
	// 		Usage:       "Server where the database deployed on, if not set, is localhost", // 命令说明
	// 		Value:       "localhost",                                                       // 默认值
	// 		Destination: &(common.Server),                                                  // 赋值
	// 	},
	// 	cli.StringFlag{
	// 		Name:        "user",               // 命令名称
	// 		Usage:       "username of server", // 命令说明
	// 		Value:       "root",               // 默认值
	// 		Destination: &(common.User),       // 赋值
	// 	},
	// 	cli.StringFlag{
	// 		Name:        "pswd",             // 命令名称
	// 		Usage:       "passwd of server", // 命令说明
	// 		Value:       "123",              // 默认值
	// 		Destination: &(common.Pass),     // 赋值
	// 	},
	// }
	//add new by hzy 20-3-5
	//using option get the start height and end height
	hzyMagicFlags := []cli.Flag{
		cli.IntFlag{
			Name:        "hzyshead",                                                     // 命令名称
			Usage:       "Specify a start height", // 命令说明
			Value:       0,                                                              // 默认值
			Destination: &(common.GlobalStartHeight),                                    // 赋值
		},
		cli.IntFlag{
			Name:        "hzystail",                                              // 命令名称
			Usage:       "Specify a end height", // 命令说明
			Value:       0,                                                       // 默认值
			Destination: &common.GlobalEndHeight,                                 // 赋值
		},
	}
	//add end
	//app.Flags = append(app.Flags, xingMagicFlags...)
	app.Flags = append(app.Flags, hzyMagicFlags...)
	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)
	app.Flags = append(app.Flags, whisperFlags...)
	app.Flags = append(app.Flags, metricsFlags...)

	app.Before = func(ctx *cli.Context) error {
		return debug.Setup(ctx, "")
	}
	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

//add new by hzy 20-5-4
//multi threads
var ChBlockInfoWorks chan common.StructBlockInfo
var ChOutTxInfoWorks chan common.StructOutTxInfo
var ChLogInfoWorks chan common.StructLogsInfo
var ChInTxInfoWorks chan common.StructInTxInfo
var ChTokenTransferWorks chan common.StructTokenTransferInfo
var ChContractInfoWorks chan common.StructContractInfo
var ChEoaInfoWorks chan common.StructEoaInfo
var ChTraceInfoWorks chan common.StructTraceInfo
var ChUpdateContractBalanceWorks chan common.StructUpdateContractBalance
var ChCallContractWokrs chan common.StructCallContractInfo
var Sizes = 56 //the number of threads

//launch go routines
func StartWorderPools(Size int) {
	for i := 0; i < Size; i++ {
		common.GlobalSyncWg.Add(1)
		go Worker()
	}
}

// xing add 22-1-7
//process different information
func Worker() {
	for {
		select {
		case Works, ok := <-ChBlockInfoWorks: // proces block information
			if !ok {
				ChBlockInfoWorks = nil
			} else {
				InsertBlockInfoToDB(Works)
				//_=Works
			}
		case Works, ok := <-ChOutTxInfoWorks: //process External TxInfo
			if !ok {
				ChOutTxInfoWorks = nil
			} else {
				InsertOutTxToDB(Works)
				//_=Works
			}
		case Works, ok := <-ChInTxInfoWorks:
			if !ok {
				ChInTxInfoWorks = nil
			} else {
				//_=Works
				InsertInTxInfoToDB(Works)
			}
		case Works, ok := <-ChLogInfoWorks: //process loginfo
			if !ok {
				ChLogInfoWorks = nil
			} else {
				//_=Works
				InserLogInfoToDB(Works)
			}
		case Works, ok := <-ChTokenTransferWorks: //process tokentransferinfo
			if !ok {
				ChTokenTransferWorks = nil
			} else {
				//_=Works
				InsertTokenTransInfoToDB(Works)
			}
		case Works, ok := <-ChContractInfoWorks:
			if !ok {
				ChContractInfoWorks = nil
			} else {
				InsertContractInfoToDB(Works)
				//_=Works
			}
		case Works, ok := <-ChEoaInfoWorks:
			if !ok {
				ChEoaInfoWorks = nil
			} else {
				InsertEoaInfoToDB(Works)
				//_=Works
			}
		case Works, ok := <-ChTraceInfoWorks:
			if !ok {
				ChTraceInfoWorks = nil
			} else {
				InsertTraceInfoToDB(Works)
				//_=Works
			}
		case Works, ok := <-ChUpdateContractBalanceWorks:
			if !ok {
				ChUpdateContractBalanceWorks = nil
			} else {
				//_=Works
				UpdateContractBalanceToDb(Works)
			}
		case Works, ok := <-ChCallContractWokrs:
			if !ok {
				ChCallContractWokrs = nil
			} else {
				InsertCallContractInfoToDB(Works)
			}
		}
		if ChBlockInfoWorks == nil && ChOutTxInfoWorks == nil && ChLogInfoWorks == nil &&
			ChInTxInfoWorks == nil && ChTokenTransferWorks == nil && ChContractInfoWorks == nil &&
			ChEoaInfoWorks == nil && ChTraceInfoWorks == nil && ChUpdateContractBalanceWorks == nil &&
			ChCallContractWokrs == nil {
			common.GlobalSyncWg.Done()
			return
		}
	}
}

//add new by hzy 20-8-28
var Mysqldbfd *sql.DB

//add end

//add end
func main() {
	//add new by hzy 20-5-4
	//multi thread design
	ChBlockInfoWorks = make(chan common.StructBlockInfo, 10000)
	ChOutTxInfoWorks = make(chan common.StructOutTxInfo, 50000)
	ChLogInfoWorks = make(chan common.StructLogsInfo, 50000)
	ChInTxInfoWorks = make(chan common.StructInTxInfo, 50000)
	ChTokenTransferWorks = make(chan common.StructTokenTransferInfo, 10000)
	ChContractInfoWorks = make(chan common.StructContractInfo, 20000)
	ChEoaInfoWorks = make(chan common.StructEoaInfo, 50000)
	ChTraceInfoWorks = make(chan common.StructTraceInfo, 10000)
	ChUpdateContractBalanceWorks = make(chan common.StructUpdateContractBalance, 10000)
	ChCallContractWokrs = make(chan common.StructCallContractInfo, 50000)

	common.GlobalSyncWg = sync.WaitGroup{}
	common.PreInsertWg = sync.WaitGroup{}
	common.GlobalChBlockInfo = ChBlockInfoWorks
	common.GlobalChOutTxInfo = ChOutTxInfoWorks
	common.GlobalChLogInfo = ChLogInfoWorks
	common.GlobalChInTxInfo = ChInTxInfoWorks
	common.GlobalChTokenTransInfo = ChTokenTransferWorks
	common.GlobalChContractInfo = ChContractInfoWorks
	common.GlobalChEoaInfo = ChEoaInfoWorks
	common.GlobalChTraceInfo = ChTraceInfoWorks
	common.GlobalUpdateContractBalanceInfo = ChUpdateContractBalanceWorks
	common.GlobalChCallContractInfo = ChCallContractWokrs
	StartWorderPools(Sizes)
	//add end
	common.StartTime = time.Now()
	common.InitialGethTime = time.Now().UnixNano()
	common.ResetOriginalFlag = true

	common.GlobalContractInsertedFlag = make(map[string]struct{})

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	//add new by hzys on 20-8-28
	//db init process
	dbtmp, Sqlerror := sql.Open("mysql", "root:123@tcp(localhost:3306)/Test?charset=utf8")
	if Sqlerror != nil {
		panic(Sqlerror)
		return
	}
	Mysqldbfd = dbtmp
	defer dbtmp.Close()
	//add end

}

// prepare manipulates memory cache allowance and setups metric system.
// This function should be called before launching devp2p stack.
func prepare(ctx *cli.Context) {
	// If we're a full node on mainnet without --cache specified, bump default cache allowance
	if ctx.GlobalString(utils.SyncModeFlag.Name) != "light" && !ctx.GlobalIsSet(utils.CacheFlag.Name) && !ctx.GlobalIsSet(utils.NetworkIdFlag.Name) {
		// Make sure we're not on any supported preconfigured testnet either
		if !ctx.GlobalIsSet(utils.TestnetFlag.Name) && !ctx.GlobalIsSet(utils.RinkebyFlag.Name) && !ctx.GlobalIsSet(utils.GoerliFlag.Name) && !ctx.GlobalIsSet(utils.DeveloperFlag.Name) {
			// Nope, we're really on mainnet. Bump that cache up!
			log.Info("Bumping default cache on mainnet", "provided", ctx.GlobalInt(utils.CacheFlag.Name), "updated", 4096)
			ctx.GlobalSet(utils.CacheFlag.Name, strconv.Itoa(4096))
		}
	}
	// If we're running a light client on any network, drop the cache to some meaningfully low amount
	if ctx.GlobalString(utils.SyncModeFlag.Name) == "light" && !ctx.GlobalIsSet(utils.CacheFlag.Name) {
		log.Info("Dropping default light client cache", "provided", ctx.GlobalInt(utils.CacheFlag.Name), "updated", 128)
		ctx.GlobalSet(utils.CacheFlag.Name, strconv.Itoa(128))
	}
	// Cap the cache allowance and tune the garbage collector
	var mem gosigar.Mem
	// Workaround until OpenBSD support lands into gosigar
	// Check https://github.com/elastic/gosigar#supported-platforms
	if runtime.GOOS != "openbsd" {
		if err := mem.Get(); err == nil {
			allowance := int(mem.Total / 1024 / 1024 / 3)
			if cache := ctx.GlobalInt(utils.CacheFlag.Name); cache > allowance {
				log.Warn("Sanitizing cache to Go's GC limits", "provided", cache, "updated", allowance)
				ctx.GlobalSet(utils.CacheFlag.Name, strconv.Itoa(allowance))
			}
		}
	}
	// Ensure Go's GC ignores the database cache for trigger percentage
	cache := ctx.GlobalInt(utils.CacheFlag.Name)
	gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

	log.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
	godebug.SetGCPercent(int(gogc))

	// Start metrics export if enabled
	utils.SetupMetrics(ctx)

	// Start system runtime metrics collection
	go metrics.CollectProcessMetrics(3 * time.Second)
}

// geth is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func geth(ctx *cli.Context) error {
	if args := ctx.Args(); len(args) > 0 {
		return fmt.Errorf("invalid command: %q", args[0])
	}
	fmt.Println("==========================\nStart Height:", common.GlobalStartHeight, "\n\n\nEnd Height", common.GlobalEndHeight, "\n==========================\n")
	prepare(ctx)
	node := makeFullNode(ctx)
	defer node.Close()
	startNode(ctx, node)
	node.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node) {
	debug.Memsize.Add("node", stack)

	// Start up the node itself
	utils.StartNode(stack)

	// Unlock any account specifically requested
	unlockAccounts(ctx, stack)

	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	// Create a client to interact with local geth node.
	rpcClient, err := stack.Attach()
	if err != nil {
		utils.Fatalf("Failed to attach to self: %v", err)
	}
	ethClient := ethclient.NewClient(rpcClient)

	// Set contract backend for ethereum service if local node
	// is serving LES requests.
	if ctx.GlobalInt(utils.LightLegacyServFlag.Name) > 0 || ctx.GlobalInt(utils.LightServeFlag.Name) > 0 {
		var ethService *eth.Ethereum
		if err := stack.Service(&ethService); err != nil {
			utils.Fatalf("Failed to retrieve ethereum service: %v", err)
		}

		ethService.SetContractBackend(ethClient)
	}
	// Set contract backend for les service if local node is
	// running as a light client.
	if ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
		var lesService *les.LightEthereum
		if err := stack.Service(&lesService); err != nil {
			utils.Fatalf("Failed to retrieve light ethereum service: %v", err)
		}
		lesService.SetContractBackend(ethClient)
	}

	go func() {
		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				var derivationPaths []accounts.DerivationPath
				if event.Wallet.URL().Scheme == "ledger" {
					derivationPaths = append(derivationPaths, accounts.LegacyLedgerBaseDerivationPath)
				}
				derivationPaths = append(derivationPaths, accounts.DefaultBaseDerivationPath)

				event.Wallet.SelfDerive(derivationPaths, ethClient)

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Spawn a standalone goroutine for status synchronization monitoring,
	// close the node when synchronization is complete if user required.
	if ctx.GlobalBool(utils.ExitWhenSyncedFlag.Name) {
		go func() {
			sub := stack.EventMux().Subscribe(downloader.DoneEvent{})
			defer sub.Unsubscribe()
			for {
				event := <-sub.Chan()
				if event == nil {
					continue
				}
				done, ok := event.Data.(downloader.DoneEvent)
				if !ok {
					continue
				}
				if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute {
					log.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
						"age", common.PrettyAge(timestamp))
					stack.Stop()
				}
			}
		}()
	}

	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
		// Mining only makes sense if a full Ethereum node is running
		if ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
			utils.Fatalf("Light clients do not support mining")
		}
		var ethereum *eth.Ethereum
		if err := stack.Service(&ethereum); err != nil {
			utils.Fatalf("Ethereum service not running: %v", err)
		}
		// Set the gas price to the limits from the CLI and start mining
		gasprice := utils.GlobalBig(ctx, utils.MinerLegacyGasPriceFlag.Name)
		if ctx.IsSet(utils.MinerGasPriceFlag.Name) {
			gasprice = utils.GlobalBig(ctx, utils.MinerGasPriceFlag.Name)
		}
		ethereum.TxPool().SetGasPrice(gasprice)

		threads := ctx.GlobalInt(utils.MinerLegacyThreadsFlag.Name)
		if ctx.GlobalIsSet(utils.MinerThreadsFlag.Name) {
			threads = ctx.GlobalInt(utils.MinerThreadsFlag.Name)
		}
		if err := ethereum.StartMining(threads); err != nil {
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}

// unlockAccounts unlocks any account specifically requested.
func unlockAccounts(ctx *cli.Context, stack *node.Node) {
	var unlocks []string
	inputs := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for _, input := range inputs {
		if trimmed := strings.TrimSpace(input); trimmed != "" {
			unlocks = append(unlocks, trimmed)
		}
	}
	// Short circuit if there is no account to unlock.
	if len(unlocks) == 0 {
		return
	}
	// If insecure account unlocking is not allowed if node's APIs are exposed to external.
	// Print warning log to user and skip unlocking.
	if !stack.Config().InsecureUnlockAllowed && stack.Config().ExtRPCEnabled() {
		utils.Fatalf("Account unlock with HTTP access is forbidden!")
	}
	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	for i, account := range unlocks {
		unlockAccount(ks, account, i, passwords)
	}
}

//add new by hzy 20-5-2
// Insert block data to hbase
func InsertBlockInfoToDB(BlockInfo common.StructBlockInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO Block (TimeStamp,BlockNumber,BlockHash,BlockParentHash,Nonce,
		UncleHash,LogsBloom,TxsRoot,StateRoot,ReceiptRoot,Miner,Difficulty,Td,Size,ExtraData,GasLimit,GasUsed,TxNums) 
		values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("Block", err)
	defer stmt.Close()

	_, err = stmt.Exec(BlockInfo.StrTimeStamp, BlockInfo.StrBlockNumber, BlockInfo.StrBlockHash, BlockInfo.StrBlockParentHash,
		BlockInfo.StrNonce, BlockInfo.StrUncleHash, BlockInfo.StrLogsBloom, BlockInfo.StrTransactionsRoot,
		BlockInfo.StrStateRoot, BlockInfo.StrReceiptRoot, BlockInfo.StrMiner, BlockInfo.StrDifficulty, BlockInfo.StrTotalDifficulty,
		BlockInfo.StrSize, BlockInfo.StrExtraData, BlockInfo.StrGasLimit, BlockInfo.StrGasUsed, BlockInfo.StrTransNums)
	CheckInsertErr("Block", err)
}

//add end

//add new  by hzy 20-5-3
//Insert external Txs information to hbase
func InsertOutTxToDB(OutTxInfo common.StructOutTxInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO OutTx(TxHash,BlockNumber,BlockHash,TimeStamp,TxIndex,
	Tag,FromAddress,ToAddress,Value,GasLimit,GasUsed,GasPrice,InputData,Nonce,ToType,FromType,TxStatus)values
	(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("OutTx", err)
	defer stmt.Close()

	var SzStatusTmp string // transfer the bool type of txstatus to string type
	if OutTxInfo.TxStatus {
		SzStatusTmp = "1"
	} else {
		SzStatusTmp = "0"
	}
	_, err = stmt.Exec(OutTxInfo.TxHash, OutTxInfo.BlockNumber, OutTxInfo.BlockHash, OutTxInfo.TimeStamp,
		strconv.Itoa(OutTxInfo.TxIndex), OutTxInfo.Tag, OutTxInfo.FromAddress, OutTxInfo.ToAddress, OutTxInfo.Value,
		OutTxInfo.GasLimit, OutTxInfo.GasUsed, OutTxInfo.GasPrice, OutTxInfo.InputData, OutTxInfo.Nonce,
		OutTxInfo.ToType, OutTxInfo.FromType, SzStatusTmp)
	CheckInsertErr("OutTx", err)

}

//add end

//add new by hzy 20-5-7
//To insert log info in db
func InserLogInfoToDB(LogInfo common.StructLogsInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO Log(BlockLogIndex,BlockTimeStamp,BlockNumber,BlockHash,
	TxHash, TxIndex,OriginatedAddress, Data, Topics) values(?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("LogInfo", err)
	defer stmt.Close()

	_, err = stmt.Exec(LogInfo.SzBlockLogIndex, LogInfo.SzBlockTimeStamp, LogInfo.SzBlockNumber, LogInfo.SzBlockHash,
		LogInfo.SzTxHash, LogInfo.SzTxIndex, LogInfo.SzOriginatedAddress, LogInfo.SzData, LogInfo.SzTopics)
	CheckInsertErr("LogInfo", err)
}

//add end

//add new by hzy 20-5-8
//To insert the inTx to hbase
func InsertInTxInfoToDB(InTxInfo common.StructInTxInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO InTx(TxCallSeq,TxLayer,TxHash,FromAddr,ToAddr,InputData,
					Value,Tag,FromType,ToType,IntrinsicGas,GasUsed,Error) values(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("InTxInfo", err)
	defer stmt.Close()
	_, err = stmt.Exec(InTxInfo.TxCallSeq, InTxInfo.TxLayer, InTxInfo.TxHash, InTxInfo.FromAddress, InTxInfo.ToAddress, InTxInfo.InputData,
		InTxInfo.Value, InTxInfo.Tag, InTxInfo.FromType, InTxInfo.ToType, InTxInfo.IntrinsicGas, InTxInfo.GasUsed, InTxInfo.Errors)
	CheckInsertErr("InTxInfo", err)

}

//add end

//add new by hzy 20-5-11
//To write tokentransfertoHbase
func InsertTokenTransInfoToDB(TokenTransInfo common.StructTokenTransferInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO TokenTrans(TokenAddr,FromAddr,ToAddr,Value,
	TxHash,LogIndex,BlockTimeStamp,BlockNumber,BlockHash) values(?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("TokenTrans", err)
	defer stmt.Close()

	_, err = stmt.Exec(TokenTransInfo.SzTokenAddr, TokenTransInfo.SzFromAddr, TokenTransInfo.SzToAddr, TokenTransInfo.SzValue,
		TokenTransInfo.SzTxHash, TokenTransInfo.SzLogIndex, TokenTransInfo.SzBlockTimeStamp, TokenTransInfo.SzBlockNumber,
		TokenTransInfo.SzBlockHash)
	CheckInsertErr("TokenTrans", err)
}

//add end

//add new by hzy 20-5-14
//insert contract info into hbase
func InsertContractInfoToDB(ContractInfo common.StructContractInfo) {
	stmt, err := Mysqldbfd.Prepare(`REPLACE INTO Contract(Address,Balance,Bytecode,MethodId,
	BlockTimeStamp,BlockNumber,BlockHash,IsERC20,Nonce) values(?,?,?,?,?,?,?,?,?)`)
	CheckInsertErr("Contract", err)
	defer stmt.Close()

	_, err = stmt.Exec(ContractInfo.Address, ContractInfo.Balance, ContractInfo.Bytecode, ContractInfo.MethodId,
		ContractInfo.BlockTimeStamp, ContractInfo.BlockNumber, ContractInfo.BlockHash, ContractInfo.IsERC20,
		ContractInfo.Nonce)
	CheckInsertErr("Contract", err)
}

//add new by hzy 20-5-14
//insert contract info into hbase
func InsertCallContractInfoToDB(CallContractInfo common.StructCallContractInfo) {
	stmt, err := Mysqldbfd.Prepare(`REPLACE INTO CallContract(Address,Bytecode) values(?,?)`)
	CheckInsertErr("CallContract", err)
	defer stmt.Close()
	_, err = stmt.Exec(CallContractInfo.Address, CallContractInfo.Bytecode)
	CheckInsertErr("CallContract", err)
}

//insertEoaInfoToHbase
func InsertEoaInfoToDB(EoaInfo common.StructEoaInfo) {
	stmt, err := Mysqldbfd.Prepare(`REPLACE INTO Eoa(Address,TimeStamp,Balance,Nonce) values(?,?,?,?)`)//xing add new 
	CheckInsertErr("EOA", err)
	defer stmt.Close()
	_, err = stmt.Exec(EoaInfo.Address, EoaInfo.TimeStamp, EoaInfo.Balance, EoaInfo.Nonce)
	CheckInsertErr("Eoa", err)
}

//add end

//add new by hzy 20-5-18
//To insert traceinfo to hbase
func InsertTraceInfoToDB(TraceInfo common.StructTraceInfo) {
	stmt, err := Mysqldbfd.Prepare(`INSERT INTO Trace(TxHash,TxTrace,ToAddress,OutOfGasTrace) values(?,?,?,?)`)
	CheckInsertErr("Trace", err)
	defer stmt.Close()
	_, err = stmt.Exec(TraceInfo.SzExternalTxHash, TraceInfo.SzTraces, TraceInfo.SzToAddress, TraceInfo.SzOutOfGasTrace)
	CheckInsertErr("Trace", err)
}

func UpdateContractBalanceToDb(UpdateContractInfo common.StructUpdateContractBalance) {
	stmt, err := Mysqldbfd.Prepare(`UPDATE Contract set Balance = ?,Nonce = ? WHERE Address = ?`)
	CheckInsertErr("Contract(update)", err)
	defer stmt.Close()
	_, err = stmt.Exec(UpdateContractInfo.Balance, UpdateContractInfo.Nonce, UpdateContractInfo.ContractAddr)
	CheckInsertErr("Contract(update)", err)
}

func CheckInsertErr(table string, err error) {
	if err != nil {
		fmt.Println("insert errors on"+table+" is ", err)
	}
}
