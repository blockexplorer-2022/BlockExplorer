package common

import "time"

var PeerDropFlag chan bool

//add new by hzy 4-30
//start sync by txs
var GlobalTotalExecNum int
var IntGlobalSyncCounter int
//add end

//add new by hzy 20-5-19
//To write state to trie
var StateWriteFlag bool
//add end

//add new by hzy 20-5-24
//to record the time
var LaunchTime int64
var StartTime time.Time
//add end

//add by hzy 20-10-19
var TxNums int
var TxGapCounter int
var CallNums int
var CallGapCounter int
var TimeGapCounter int
var CurrentBlockNumber string
//add end

var StateWriteMap map[int64]bool
var TmpArray string
