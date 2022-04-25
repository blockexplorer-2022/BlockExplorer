## Introduction
BlockExplorer is an efficient, scalable, and flexible blockchain-exploration system on Ethereum. At a high level, BlockExplorer first acquires data from instrumented Ethereum nodes and then efficiently processes the data in parallel on a cluster of computers. Particularly, to tackle the inefficient data collection problem, we propose techniques to enable partitioned and parallel blockchain synchronization and deferred smart-contract executions.
## Dependency
A cluster with one master machine and multiple slave nodes. 
```
Go (version 1.13.6 or later) and a C compiler.
MySQL Server (version 5.7.35 or later)
```
## Build and Run

### Run Master
Downloading go-ethereum-master, then set your segmentation point of the height of Block at ```InitStateWrite```function in [go-ethereum-master/cmd/geth/main.go](https://gitee.com/Rainshyabc/block-explorer-geth-master/blob/master/cmd/geth/main.go) file,```ContractCallGapPoint``` is a sample example. For example, if you want to synchronize from the specific 1000 Block, you should add point of 1000. 
then build geth-master by running
```make geth```
after that, start a Ethereum node by running
```
geth --datadir data --syncmode full
```
Then master will download blockchain data from Ethereum mainnet node, you could use ```geth --help``` for more options.
After starting synchronization,  you need to record your current master node informations which is used for slave nodes to attach.

### Run Slave
For each slave nodes:
Firstly, building the tables that used to storage all types of data with [Tables.sql](./block-explorer-geth-slave/Tables.sql).
then modify your master node information at line 495 in go-ethereum-slave/p2p/server.go file.
```	
addHzyPeerAddr("enode://7f98ddd58029d087b10353421fd69584f78e1bc82f70a55890faf8559c25e6f4f0e902e419495c1ec1bf4466b2826d1ff8a4e9ca4d8806a9452111b2950facf7@192.168.1.152:30303?discport=0")
```
configure your mysql connection at line 405-406 in go-ethereum-slave/cmd/geth/main.go file,
```dbtmp,Sqlerror:=sql.Open("mysql","root:123@tcp(slave2:3306)/Eth3000?charset=utf8")```
then build geth-slave by running
```make geth```
, after that, start the synchronization by running the following command to start at a specific range blocknumber. Note that the ```startBlockNumber``` must have sychronized by master node because slave is synchronizing data from the master node.
```geth --datadir data-slave --syncmode fast -hzyshead startBlockNumber --hzystail endBlockNumber```
