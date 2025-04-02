using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Timers;
using MessagePack;
using System.Data;

namespace Nexus
{
    class Nexus_Monohash
    {
        static string privateAddressLocation = $"{AppContext.BaseDirectory}addresses\\private.dat";
        static string publicAddressLocation = $"{AppContext.BaseDirectory}addresses\\public.dat";
        static string addressesLocation = $"{AppContext.BaseDirectory}addresses\\addresses.dat";
        static string peersLocation = $"{AppContext.BaseDirectory}peers\\peers.dat";
        static string blockedPeersLocation = $"{AppContext.BaseDirectory}peers\\blockedPeers.dat";
        static string UTXOSetLocation = $"{AppContext.BaseDirectory}UTXOSet\\UTXOSet.dat";
        static bool headerFileOpen = false;
        static string blockHeadersLocation = $"{AppContext.BaseDirectory}blockHeaders\\blockHeaders.dat";
        static TcpListener listener = new TcpListener(IPAddress.Any, 012009);
        static Task blockQuery;
        static Task peersQuery;
        static Task memoryPoolQuery;
        static Task broadcast;
        static Task peerListBroadcast;
        static Task generatingBlockTask;
        static CancellationTokenSource generatingBlock = new();
        static bool isValidating;
        static List<BroadcastTransaction> memoryPool = new List<BroadcastTransaction>();
        static List<Peer> peerList = new List<Peer>();
        class Peer
        {
            public string peerAddress = "";
            public Stopwatch communicationTimer = new Stopwatch();
            public Peer (string PeerAddress)
            {
                peerAddress = PeerAddress;
            }
        }
        //starting difficulty will take roughly a minute and a half with network hash rate of 400Kh/s
        static float difficultyLevel = 25;
        [MessagePackObject]
        public class BroadcastTransaction
        {
            [Key(0)]
            public Transaction output;
            [Key(1)]
            public string signature;
            [Key(2)]
            public string transactionID;
            public BroadcastTransaction() { }
            public BroadcastTransaction(Transaction Output, string Signature, string TransactionID)
            {
                output = Output;
                signature = Signature;
                transactionID = TransactionID;
            }
            [Key(3)]
            public int setBlockTag;
            [Key(4)]
            public List<BroadcastTransaction> unspentOutputs = new List<BroadcastTransaction>(); 
        }
        [MessagePackObject]
        public class Transaction
        {
            [Key(0)]
            public float sentAmount;
            [Key(1)]
            public float networkFee;
            [Key(2)]
            public string receiverAddress;
            [Key(3)]
            public string senderAddress;
            [SerializationConstructor]
            public Transaction(float SentAmount, float NetworkFee, string ReceiverAddress, string SenderAddress)
            {
                networkFee = NetworkFee;
                sentAmount = SentAmount;
                receiverAddress = ReceiverAddress;
                senderAddress = SenderAddress;
            }
        }
        [MessagePackObject]
        public class MerkleBranch
        {
            [Key(0)]
            public string hash;
            [Key(1)]
            public Tuple<MerkleBranch, MerkleBranch> merkleChildren; 
            [Key(2)]
            public BroadcastTransaction dataBlock = null;
        }
        [MessagePackObject]
        public class Block
        {
            [Key(0)]
            public int blockCount = 0;
            [Key(1)]
            public float timeBetweenLastBlock;
            [Key(2)]
            public BlockHeader blockHeader = new BlockHeader();
            [Key(3)]
            public MerkleBranch merkleRoot;
            [Key(4)]
            public string hash;
        }
        [MessagePackObject]
        public class BlockHeader
        {
            [Key(0)]
            public string merkleRootHash = "";
            [Key(1)]
            public long time;
            [Key(2)]
            public string previousHash = "";
            [Key(3)]
            public int nonce;
            [Key(4)]
            public float blockDifficulty;
        }
        static string blockReceivedMiner = "";
        static void SignTransaction()
        {
            byte[] bytesUTXOSet = File.ReadAllBytes(UTXOSetLocation);
            List<BroadcastTransaction> UTXOSet = new List<BroadcastTransaction>();
            if(bytesUTXOSet.Length > 0)
            {
                UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
            }
            else
            {
                Console.WriteLine("Empty Blockchain.");
                Task.Run(Menu);
                return;
            }
            string privateKeyBase64 = MessagePackSerializer.Deserialize<string>(File.ReadAllBytes(privateAddressLocation));
            string publicKeyBase64 = MessagePackSerializer.Deserialize<string>(File.ReadAllBytes(publicAddressLocation));
            // Create a new ECDsa instance using the private key
            using (ECDsa ecdsa = ECDsa.Create())
            {
                ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);

                Console.WriteLine("Receiver:");
                string receiver = Console.ReadLine();
                Console.WriteLine("Amount:");
                string amount = Console.ReadLine();
                Console.WriteLine("Network fee:");
                string networkFee = Console.ReadLine();

                Transaction transaction = new Transaction(float.Parse(amount), float.Parse(networkFee), receiver, publicKeyBase64);
                BroadcastTransaction broadcast = new BroadcastTransaction(null, null, "");
                List<BroadcastTransaction> UTXOs = new List<BroadcastTransaction>();
                float valueOfUTXOs = 0;
                foreach (BroadcastTransaction utxo in UTXOSet)
                {
                    if(valueOfUTXOs >= float.Parse(amount) + float.Parse(networkFee))
                        break;
                    if(utxo.output.receiverAddress == publicKeyBase64)
                    {
                        valueOfUTXOs += utxo.output.sentAmount;
                        UTXOs.Add(utxo);
                    }
                }
                broadcast.unspentOutputs = UTXOs;
                broadcast.transactionID = ComputeSHA256Hash(transaction.ToString() + broadcast.unspentOutputs.ToString());

                byte[] dataBytes = Encoding.UTF8.GetBytes(transaction.ToString());

                // Sign the data
                byte[] signature = ecdsa.SignData(dataBytes, HashAlgorithmName.SHA256);
                string signatureString = Convert.ToBase64String(signature);

                broadcast.signature = signatureString;
                broadcast.output = transaction;
                Task.Run(() => PropagateTransaction(broadcast));
                Task.Run(Menu);
                memoryPool.Add(broadcast);
            }
        }
        static async Task PropagateTransaction(BroadcastTransaction broadcast)
        {
            Stopwatch timer = new Stopwatch();
            timer.Start();
            List<string> peersPropagatedTo = new List<string>();
            while (timer.Elapsed.TotalSeconds < 10)
            {
                if(timer.ElapsedMilliseconds % 100 == 0)
                {
                    for (int peer = 0; peer < peerList.Count; peer++)
                    {
                        if(peerList[peer].communicationTimer.Elapsed.Minutes >= 10)
                            continue;
                        if(!peersPropagatedTo.Contains(peerList[peer].peerAddress))
                        {
                            using (TcpClient client = new TcpClient())
                            {
                                await client.ConnectAsync(peerList[peer].peerAddress, 012009);
                                if(client.Client.Poll(5000, SelectMode.SelectWrite))
                                {
                                    peerList[peer].communicationTimer.Restart();
                                    client.ReceiveTimeout = 100;
                                    client.SendTimeout = 100;

                                    NetworkStream stream = client.GetStream();

                                    // Send a request to the server
                                    string request = "Send Transaction";
                                    byte[] requestBytes = Encoding.UTF8.GetBytes(request);
                                    await stream.WriteAsync(requestBytes, 0, requestBytes.Length);

                                    // Receive the response from the server
                                    byte[] responseBuffer = new byte[256];
                                    int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
                                    string response = Encoding.UTF8.GetString(responseBuffer, 0, bytesRead);

                                    if(response == "Accept Transaction")
                                    {
                                        peersPropagatedTo.Add(peerList[peer].peerAddress);
                                        // Send a request to the server
                                        byte[] transactionBytes = MessagePackSerializer.Serialize(broadcast);
                                        await stream.WriteAsync(transactionBytes, 0, transactionBytes.Length);
                                        peerList[peer].communicationTimer.Restart();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    
        static void WalletInspector()
        {
            Console.WriteLine("Wallet address:");
            string walletAddress = Console.ReadLine();
            byte[] bytesUTXOSet = File.ReadAllBytes(UTXOSetLocation);
            if(bytesUTXOSet.Length != 0)
            {
                List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
                Console.WriteLine();
                Console.WriteLine($"Wallet contains {CheckAddressFunds(UTXOSet, walletAddress):G} nexus.");
            }
            else
            {
                Console.WriteLine("Empty blockchain.");
            }
            Console.ReadLine();
            Task.Run(Menu);
        }
        static async Task Main()
        {
            List<string> peers = new List<string>();
            byte[] bytes = File.ReadAllBytes(peersLocation);
            if(bytes.Length > 0)
                peers = MessagePackSerializer.Deserialize<List<string>>(bytes);
            foreach (string peer in peers)
            {
                Peer newPeer = new Peer(peer);
                newPeer.communicationTimer.Start();
                peerList.Add(newPeer);
            }
            listener.Start();
            Console.ForegroundColor = ConsoleColor.White;
            System.Timers.Timer timer = new System.Timers.Timer(100);
            //use a timer to query the network 10 times a second
            timer.Elapsed += QueryNodes;
            timer.AutoReset = true; 
            timer.Enabled = true; 
            System.Timers.Timer timerExitCheck = new System.Timers.Timer(1000);
            //use a timer to query the network 10 times a second
            timerExitCheck.Elapsed += ExitWithInput;
            timerExitCheck.AutoReset = true; 
            timerExitCheck.Enabled = true; 
            await Menu();
            await Task.Delay(-1);
        }
        static async Task Menu()
        {
            Console.WriteLine("Nexus Monohash v1.0");
            Console.WriteLine("---------------------");
            Console.WriteLine("1: Generate New Address");
            Console.WriteLine("2: View Addresses");  
            Console.WriteLine("3: Run Validator");
            Console.WriteLine("4: Sign Transaction");
            Console.WriteLine("5: Add Peer");  
            Console.WriteLine("6: Check Wallet Funds");  

            string optionPicked = Console.ReadLine();
            switch (optionPicked)
            {
                case "1": 
                    GenerateAddresses();
                    break;
                case "2": 
                    Addresses();
                    break;    
                case "3": 
                    generatingBlockTask = Task.Run(() => GenerateBlock(generatingBlock.Token));
                    break;
                case "4": 
                    SignTransaction();
                    break;   
                case "5": 
                    AddPeer();
                    break;
                case "6": 
                    WalletInspector();
                    break;
            }
        }
        static void AddPeer()
        {
            if(peerList.Count > 0)
            {
                foreach (Peer peer in peerList)
                {
                    Console.WriteLine("Current peers:");
                    Console.WriteLine(peer.peerAddress);
                }
            }
            Console.WriteLine("Add peer address");
            string address = Console.ReadLine();
            if(address != "")
            {
                Peer newPeer = new Peer(address);
                newPeer.communicationTimer.Start();
                peerList.Add(newPeer);
            }
            List<string> peers = peerList.Select(item => item.peerAddress).ToList();
            File.WriteAllBytes(peersLocation, MessagePackSerializer.Serialize(peers));
            Task.Run(Menu);
        }
        static MerkleBranch CreateMerkleTree(List<BroadcastTransaction> transactions)
        {
            List<MerkleBranch> dataBlocks = new List<MerkleBranch>();
            for (int i = 0; i < transactions.Count; i ++)
            {
                MerkleBranch dataToAdd = new MerkleBranch();
                dataToAdd.hash = ComputeSHA256Hash(transactions[i].ToString());
                dataToAdd.dataBlock = transactions[i];
                dataBlocks.Add(dataToAdd);
            }
            List<MerkleBranch> merkleBranches = new List<MerkleBranch>();
            for (int i = 0; i < dataBlocks.Count; i += 2)
            {
                MerkleBranch dataToAdd = new MerkleBranch();
                if (dataBlocks.Count > i + 1)
                {
                    dataToAdd.hash = ComputeSHA256Hash(dataBlocks[i].hash + dataBlocks[i + 1].hash);
                    dataToAdd.merkleChildren = new Tuple<MerkleBranch, MerkleBranch>(dataBlocks[i], dataBlocks[i + 1]);
                }
                else
                {
                    dataToAdd.hash = ComputeSHA256Hash(dataBlocks[i].hash + dataBlocks[i].hash);
                    dataToAdd.merkleChildren = new Tuple<MerkleBranch, MerkleBranch>(dataBlocks[i], null);
                }
                merkleBranches.Add(dataToAdd);
            }
            List<MerkleBranch> branchesForConstruct = new List<MerkleBranch>();
            merkleBranches.ForEach(x => branchesForConstruct.Add(x));
            merkleBranches.Clear();
            if(branchesForConstruct.Count == 1)
            {
                MerkleBranch rootBranch = branchesForConstruct[0];
                return rootBranch;
            }
            else
            {
                while(branchesForConstruct.Count > 2)
                {
                    for (int i = 0; i < branchesForConstruct.Count; i += 2)
                    {
                        MerkleBranch dataToAdd = new MerkleBranch();
                        if (branchesForConstruct.Count > i + 1)
                        {
                            dataToAdd.hash = ComputeSHA256Hash(branchesForConstruct[i].hash + branchesForConstruct[i + 1].hash);
                            dataToAdd.merkleChildren = new Tuple<MerkleBranch, MerkleBranch>(branchesForConstruct[i], branchesForConstruct[i + 1]);
                        }
                        else
                        {
                            dataToAdd.hash = ComputeSHA256Hash(branchesForConstruct[i].hash + branchesForConstruct[i].hash);
                            dataToAdd.merkleChildren = new Tuple<MerkleBranch, MerkleBranch>(branchesForConstruct[i], null);
                        }
                        merkleBranches.Add(dataToAdd);
                    }
                    branchesForConstruct.Clear();
                    merkleBranches.ForEach(x => branchesForConstruct.Add(x));
                    merkleBranches.Clear();
                }
                MerkleBranch rootBranch = new MerkleBranch();
                rootBranch.merkleChildren = new Tuple<MerkleBranch, MerkleBranch>(branchesForConstruct[0], branchesForConstruct[1]);
                rootBranch.hash = ComputeSHA256Hash(branchesForConstruct[0].hash + branchesForConstruct[1].hash);
                return rootBranch;
            }
        }
        static List<BroadcastTransaction> TransactionsFromMerkleTree(MerkleBranch merkleBranch)
        {
            List<BroadcastTransaction> transactions = new List<BroadcastTransaction>();
            CheckIfTransaction(merkleBranch, transactions);
            return transactions;
        }
        static void CheckIfTransaction(MerkleBranch branch, List<BroadcastTransaction> transactions)
        {
            if(branch.merkleChildren.Item1.dataBlock != null)
            {
                if(branch.merkleChildren.Item1 .dataBlock.output.senderAddress == "blockReward")
                    blockReceivedMiner = branch.merkleChildren.Item1.dataBlock.output.receiverAddress;
                transactions.Add(branch.merkleChildren.Item1.dataBlock);
                if(branch.merkleChildren.Item2 != null)
                {
                    if(branch.merkleChildren.Item2.dataBlock.output.senderAddress == "blockReward")
                        blockReceivedMiner = branch.merkleChildren.Item2.dataBlock.output.receiverAddress;
                    transactions.Add(branch.merkleChildren.Item2.dataBlock);
                }
            }
            else    
            {
                CheckIfTransaction(branch.merkleChildren.Item1, transactions);
                CheckIfTransaction(branch.merkleChildren.Item2, transactions);
            }
        }
        static bool CheckMerkleTreeValidity(MerkleBranch merkleBranch)
        {
            return CheckMerkleBranchValidity(merkleBranch);;
        }
        static bool CheckMerkleBranchValidity(MerkleBranch branch)
        {
            if(branch.merkleChildren != null)
            {
                if(branch.merkleChildren.Item2 != null)
                {
                    if(branch.hash != ComputeSHA256Hash(branch.merkleChildren.Item1.hash + branch.merkleChildren.Item2.hash))
                        return false;
                    else
                    {
                        bool valid = CheckMerkleBranchValidity(branch.merkleChildren.Item1);
                        if(valid)
                            valid = CheckMerkleBranchValidity(branch.merkleChildren.Item2);
                        else                        
                            return false;
                        if(!valid)  
                            return false;
                    }
                }
                else
                {
                    if(branch.hash != ComputeSHA256Hash(branch.merkleChildren.Item1.hash + branch.merkleChildren.Item1.hash))
                        return false;
                    else
                    {
                        bool valid = CheckMerkleBranchValidity(branch.merkleChildren.Item1);
                        if(!valid)
                            return false;
                    }
                }
            }
            else 
            {
                if (branch.dataBlock != null)
                {
                    if(branch.hash != ComputeSHA256Hash(branch.dataBlock.ToString()))
                        return false;
                }
            }
            return true;
        }
        static async Task GenerateBlock(CancellationToken token)
        {
            isValidating = true;
            byte[] bytesAddress = await File.ReadAllBytesAsync(publicAddressLocation);
            if(peerList.Count == 0)
            {
                Console.WriteLine("No peers selected");
                isValidating = false;
                Task.Run(Menu);
                return;
            }
            else if (bytesAddress.Length == 0)
            {
                Console.WriteLine("No address generated");
                isValidating = false;
                Task.Run(Menu);
                return;
            }
            while(headerFileOpen)
                await Task.Delay(10);
            headerFileOpen = true;
            byte[] bytesBlockHeaders = await File.ReadAllBytesAsync(blockHeadersLocation);
            List<BlockHeader> blockHeaders = new List<BlockHeader>();
            headerFileOpen = false;
            if(Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length == 0)
            {
                //hard coded genesis block so nodes can agree on a starting point in every chain
                Block genesisBlock = new Block();
                genesisBlock.blockCount = 0;
                genesisBlock.blockHeader.blockDifficulty = 25;
                Transaction blockRewardTX = new Transaction(1, 0,"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBvZcgatfCAW24d9bqkMxoFEmJWvHs2jQ9nBG+SXlPkarwZaxqf6ckOkCbqR1e/WkDrMksSnM4duEMyj7iRjp26cIA/VHaVuSCMA8R/JpgSbinyK7ChEKju1B/7dXY6X3Sh0/qD+KwZoO7MmOBKx8ZYsppqRsRc7yCUYNM1SI4dH5MoBw=", "blockReward");
                BroadcastTransaction blockReward = new BroadcastTransaction(blockRewardTX, "blockReward", ComputeSHA256Hash(blockRewardTX.ToString()));
                Transaction networkFeesTX = new Transaction(0, 0, "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBvZcgatfCAW24d9bqkMxoFEmJWvHs2jQ9nBG+SXlPkarwZaxqf6ckOkCbqR1e/WkDrMksSnM4duEMyj7iRjp26cIA/VHaVuSCMA8R/JpgSbinyK7ChEKju1B/7dXY6X3Sh0/qD+KwZoO7MmOBKx8ZYsppqRsRc7yCUYNM1SI4dH5MoBw=", "networkFees");
                BroadcastTransaction networkFees = new BroadcastTransaction(networkFeesTX, "networkFees", ComputeSHA256Hash(networkFeesTX.ToString()));
                List<BroadcastTransaction> transactions = new List<BroadcastTransaction>{blockReward, networkFees};
                blockReward.setBlockTag = 0;
                genesisBlock.merkleRoot = CreateMerkleTree(transactions);
                genesisBlock.blockHeader.merkleRootHash = genesisBlock.merkleRoot.hash;
                genesisBlock.blockHeader.time = 1742657086;
                genesisBlock.blockHeader.nonce = 6321830;
                genesisBlock.hash = "000000241863e87fdce915a32d341385dcdb89627cbda965df22831d85e6ef83";

                blockHeaders.Add(genesisBlock.blockHeader);
                bytesBlockHeaders = MessagePackSerializer.Serialize(blockHeaders);

                while(headerFileOpen)
                    await Task.Delay(10);
                headerFileOpen = true;
                await File.WriteAllBytesAsync(blockHeadersLocation, bytesBlockHeaders);
                headerFileOpen = false;

                byte[] bytes = MessagePackSerializer.Serialize(genesisBlock);
                await File.WriteAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block0.dat", bytes);

                List<BroadcastTransaction> UTXOSet = new List<BroadcastTransaction>{blockReward};
                byte[] bytesUTXOSet = MessagePackSerializer.Serialize(UTXOSet);
                await File.WriteAllBytesAsync(UTXOSetLocation, bytesUTXOSet);
                PrintBlockData(genesisBlock);
            }
            else
            {
                blockHeaders = MessagePackSerializer.Deserialize<List<BlockHeader>>(bytesBlockHeaders);
                Block block = new Block();
                byte[] bytesLastBlock;
                bytesLastBlock = await File.ReadAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length - 1}.dat");
                Block lastBlock = MessagePackSerializer.Deserialize<Block>(bytesLastBlock);
                difficultyLevel = GetDifficultyLevel(lastBlock.blockHeader, blockHeaders);
                Console.WriteLine("Checking memory-pool for pending transactions");
                bool gatheringTransactions = true;
                List<BroadcastTransaction> transactions = new List<BroadcastTransaction>();
                int iteration = 0;
                while (gatheringTransactions)
                {
                    if(token.IsCancellationRequested)
                    {
                        generatingBlock.Dispose();
                        generatingBlock = new();
                        isValidating = false;
                        return;
                    }
                    if(memoryPool.Count == 0)
                    {
                        gatheringTransactions = false;
                    }
                    else
                    {
                        if(memoryPool.Count == iteration)
                        {
                            gatheringTransactions = false;
                        }
                        else
                        {
                            transactions.Add(memoryPool[iteration]);
                            iteration++;
                            if(Encoding.UTF8.GetByteCount(transactions.ToString()) > 1048576)
                            {
                                transactions.RemoveAt(transactions.Count - 1);
                                gatheringTransactions = false;
                            }
                        }
                    }
                }
                block.blockCount = Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length;
                RemoveDoubleSpends(transactions);
                //mint coins as a reward for mining
                string publicAddress = MessagePackSerializer.Deserialize<string>(await File.ReadAllBytesAsync(publicAddressLocation));
                float aggregateNetworkFees = 0;
                foreach (BroadcastTransaction transaction in transactions)
                    aggregateNetworkFees += transaction.output.networkFee;
                Transaction blockRewardTransaction = new Transaction(1, 0, publicAddress, "blockReward");
                BroadcastTransaction blockReward = new BroadcastTransaction(blockRewardTransaction, "blockReward", ComputeSHA256Hash(blockRewardTransaction.ToString() + block.blockCount));
                transactions.Add(blockReward);
                Transaction networkFeesTransaction = new Transaction(aggregateNetworkFees, 0, publicAddress, "networkFees");
                BroadcastTransaction networkFees = new BroadcastTransaction(networkFeesTransaction, "networkFees", ComputeSHA256Hash(networkFeesTransaction.ToString() + block.blockCount));
                transactions.Add(networkFees);
                byte[] bytesUTXOSet = await File.ReadAllBytesAsync(UTXOSetLocation);
                List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
                blockReward.setBlockTag = block.blockCount;
                UTXOSet.Add(blockReward);
                if(aggregateNetworkFees > 0)
                {
                    networkFees.setBlockTag = block.blockCount;
                    UTXOSet.Add(networkFees);
                }
                List<BroadcastTransaction> utxosToRemove = new List<BroadcastTransaction>();
                foreach (BroadcastTransaction transaction in transactions)
                {
                    if(transaction.output.senderAddress != "blockReward" && transaction.output.senderAddress != "networkFees")
                    {
                        float totalOutput = 0;
                        for (int i = 0; i < transaction.unspentOutputs.Count; i++)
                        {
                            utxosToRemove.Add(transaction.unspentOutputs[i]);
                            totalOutput += transaction.unspentOutputs[i].output.sentAmount;
                        }

                        float change = totalOutput - (transaction.output.sentAmount + transaction.output.networkFee);
                        Transaction networkChangeTransaction = new Transaction(change, 0, transaction.output.senderAddress, "networkChange");
                        BroadcastTransaction networkChange = new BroadcastTransaction(networkChangeTransaction, "networkChange", ComputeSHA256Hash(networkChangeTransaction.ToString() + block.blockCount));
                        networkChange.setBlockTag = block.blockCount;
                        UTXOSet.Add(networkChange);
                        transaction.setBlockTag = block.blockCount;
                        UTXOSet.Add(transaction);
                    }
                }
                block.merkleRoot = CreateMerkleTree(transactions);
                Console.WriteLine("Hashing block...");
                int nonce = 0;
                string hash = "";
                string binaryString = "";
                string rawData = block.merkleRoot.hash + lastBlock.hash;
                long timeBeforeHashing;
                // Create a SHA256 instance
                using (SHA256 sha256 = SHA256.Create())
                {
                    timeBeforeHashing = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    while (binaryString.TakeWhile(c => c == '0').Count() < difficultyLevel)
                    {          
                        block.blockHeader.time = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        if(token.IsCancellationRequested)
                        {
                            generatingBlock.Dispose(); 
                            generatingBlock = new();
                            isValidating = false;
                            return;
                        }
                        nonce ++;
                        if(nonce == int.MaxValue)
                            nonce = 0;
                        string rawDataWithNonce = rawData + block.blockHeader.time + nonce;

                        // Convert the input string to a byte array
                        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawDataWithNonce));
                        binaryString = string.Join(" ", bytes.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0'))).Replace(" ", "");
                    }
                    block.timeBetweenLastBlock = block.blockHeader.time - lastBlock.blockHeader.time;
                }
                for (int i = 0; i < utxosToRemove.Count; i++)
                    for (int i2 = 0; i2 < UTXOSet.Count; i2++)
                        if(UTXOSet[i2].transactionID == utxosToRemove[i].transactionID)
                            UTXOSet.RemoveAt(i2);
                hash = ComputeSHA256Hash(rawData + block.blockHeader.time + nonce);
                for (int i = 0; i < transactions.Count; i++)
                    memoryPool.Remove(transactions[i]);

                block.blockHeader.nonce = nonce;
                block.hash = hash;
                block.blockHeader.previousHash = lastBlock.hash;
                block.blockHeader.merkleRootHash = block.merkleRoot.hash;
                block.blockHeader.blockDifficulty = difficultyLevel;
                byte[] bytesBlock = MessagePackSerializer.Serialize(block);
                await File.WriteAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{block.blockCount}.dat", bytesBlock);
                
                blockHeaders.Add(block.blockHeader);
                bytesBlockHeaders = MessagePackSerializer.Serialize(blockHeaders);
                while(headerFileOpen)
                    await Task.Delay(10);
                headerFileOpen = true;
                await File.WriteAllBytesAsync(blockHeadersLocation, bytesBlockHeaders);
                headerFileOpen = false;

                bytesUTXOSet = MessagePackSerializer.Serialize(UTXOSet);
                await File.WriteAllBytesAsync(UTXOSetLocation, bytesUTXOSet);
                Console.WriteLine("Block written");
                float timeTakenToHash = block.blockHeader.time - timeBeforeHashing;
                if(timeTakenToHash > 0)
                {
                    if(timeTakenToHash > 60)
                        Console.WriteLine($"Block time: {(int)(timeTakenToHash / 60)}m {(int)(timeTakenToHash % 60):F0}s");
                    else
                    {
                        Console.WriteLine($"Block time: {timeTakenToHash:F0}s");
                    }
                    Console.WriteLine($"Hash rate: {nonce / timeTakenToHash / 1000:F0}Kh/s");
                }

                Console.WriteLine();
                PrintBlockData(block);
            }
            Task.Run(() => GenerateBlock(generatingBlock.Token));
        }
        static async Task BroadcastBlockchain()
        {
            // Asynchronously accept a client connection
            TcpClient client;
            Task<TcpClient> connect = listener.AcceptTcpClientAsync();
            Task timeout = Task.Delay(TimeSpan.FromSeconds(1));
            if(await Task.WhenAny(connect, timeout) == timeout)
                return;
            else
                client = await connect;
            if(client.Connected)
            {
                await HandleClientAsync(client);
            }
        }
        static async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            {
                using (NetworkStream stream = client.GetStream())
                {
                    client.ReceiveTimeout = 100;
                    client.SendTimeout = 100;

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        Stopwatch stopwatch = new Stopwatch();
                        stopwatch.Start();
                        while(!stream.DataAvailable)
                            if(stopwatch.Elapsed > TimeSpan.FromSeconds(3))
                                return;
                        byte[] buffer = new byte[32768];
                        int bytesRead;
                        // Read data in chunks until the server closes the connection
                        Stopwatch bytesReadTimer = new Stopwatch();
                        stopwatch.Restart();
                        bytesReadTimer.Start();

                        while (stopwatch.Elapsed < TimeSpan.FromSeconds(60))
                        {
                            if(bytesReadTimer.Elapsed > TimeSpan.FromSeconds(0.25f))
                                break;
                            try
                            {
                                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(0.25f)))
                                {
                                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                                    if (bytesRead > 0)
                                    {
                                        await memoryStream.WriteAsync(buffer, 0, bytesRead);
                                        bytesReadTimer.Restart();
                                    }
                                }
                            }
                            catch (OperationCanceledException){break;}
                            catch{break;}
                        }
                        stopwatch.Stop();
                        byte[] allData = memoryStream.ToArray();
                        if(allData.Length == 0)
                            return;
                        List<string> blockHeaders = MessagePackSerializer.Deserialize<List<string>>(allData);
                        List<string> peers = peerList.Select(item => item.peerAddress).ToList();
                        string peer = (client.Client.RemoteEndPoint as IPEndPoint).ToString().Split(":")[0];
                        if(!peers.Contains(peer))
                        {
                            peers.Add(peer);
                            Peer newPeer = new Peer(peer);
                            newPeer.communicationTimer.Start();
                            peerList.Add(newPeer);
                            peers.Add(peer);
                            byte[] bytes = MessagePackSerializer.Serialize(peers);
                            await File.WriteAllBytesAsync(peersLocation, bytes);
                        }
                        if(blockHeaders.Count > 0 && Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length > blockHeaders.Count)
                        {
                            int forkPoint = 0;
                            bool hasForkPoint = false;
                            for (int i = blockHeaders.Count - 1; i >= 0; i--)
                            {
                                byte[] bytesBlock = await File.ReadAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{i}.dat");
                                Block block = MessagePackSerializer.Deserialize<Block>(bytesBlock);
                                if(block.hash == blockHeaders[i])
                                {
                                    hasForkPoint = true;
                                    forkPoint = i;
                                    break;
                                }
                            }
                            if(hasForkPoint)
                            {
                                byte[] bytesBlock = await File.ReadAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{forkPoint + 1}.dat");
                                Block block = MessagePackSerializer.Deserialize<Block>(bytesBlock);
                                if(forkPoint != Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length - 2)
                                {
                                    while(headerFileOpen)
                                        await Task.Delay(10);
                                    headerFileOpen = true;
                                    byte[] bytesBlockHeaders = await File.ReadAllBytesAsync(blockHeadersLocation);
                                    headerFileOpen = false;
                                    List<BlockHeader> blockHeadersFile = MessagePackSerializer.Deserialize<List<BlockHeader>>(bytesBlockHeaders);

                                    Tuple<List<BlockHeader>, Block> blockHeadersResponse = new Tuple<List<BlockHeader>, Block>(new List<BlockHeader>(), block);
                                    for (int i = forkPoint + 2; i < blockHeadersFile.Count; i++)
                                    {
                                        blockHeadersResponse.Item1.Add(blockHeadersFile[i]);
                                    }
                                    byte[] responseBytesBlock = MessagePackSerializer.Serialize(blockHeadersResponse);
                                    await stream.WriteAsync(responseBytesBlock, 0, responseBytesBlock.Length);
                                }
                                else
                                {
                                    byte[] responseBytesBlock = MessagePackSerializer.Serialize(block);
                                    await stream.WriteAsync(responseBytesBlock, 0, responseBytesBlock.Length);
                                }
                            }
                            peerList[peers.IndexOf(peer)].communicationTimer.Restart();
                        }
                    }
                }
            }
        }
        static async Task BroadcastPeerList()
        {
            // Asynchronously accept a client connection
            TcpClient client;
            Task<TcpClient> connect = listener.AcceptTcpClientAsync();
            Task timeout = Task.Delay(TimeSpan.FromSeconds(1));
            if(await Task.WhenAny(connect, timeout) == timeout)
                return;
            else
                client = await connect;
            if(client.Connected)
            {
                await PeerListCommunicationAsync(client);
            }
        }
        static async Task PeerListCommunicationAsync(TcpClient client)
        {
            using (client)
            {
                using (NetworkStream stream = client.GetStream())
                {
                    client.ReceiveTimeout = 100;
                    client.SendTimeout = 100;

                    byte[] buffer = new byte[32768];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    if (request == "Requesting Peer List")
                    {
                        List<string> peers = peerList.Select(item => item.peerAddress).ToList();
                        string peer = (client.Client.RemoteEndPoint as IPEndPoint).ToString().Split(":")[0];
                        if(!peers.Contains(peer))
                        {
                            peers.Add(peer);
                            Peer newPeer = new Peer(peer);
                            newPeer.communicationTimer.Start();
                            peerList.Add(newPeer);
                            peers.Add(peer);
                            byte[] bytes = MessagePackSerializer.Serialize(peers);
                            await File.WriteAllBytesAsync(peersLocation, bytes);
                        }
                        byte[] responseBytes = MessagePackSerializer.Serialize(peers);
                        await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                        peerList[peers.IndexOf(peer)].communicationTimer.Restart();
                    }
                }
            }
        }
        static void QueryNodes(object source, ElapsedEventArgs e)
        {
            //exit communication at exception to prevent potential distributed denial of service attacks
            try
            {
                if(blockQuery != null)
                {
                    if(blockQuery.IsCompleted)
                    {
                        blockQuery = Task.Run(CheckForBlocks);
                    }
                }
                else
                {
                    blockQuery = Task.Run(CheckForBlocks);
                }
                if(peersQuery != null)
                {
                    if(peersQuery.IsCompleted)
                    {
                        peersQuery = Task.Run(CheckForPeers);
                    }
                }
                else
                {
                    peersQuery = Task.Run(CheckForPeers);
                }
                if(memoryPoolQuery != null)
                {
                    if(memoryPoolQuery.IsCompleted)
                    {
                        memoryPoolQuery = Task.Run(UpdateMemoryPool);
                    }
                }
                else
                {
                    memoryPoolQuery = Task.Run(UpdateMemoryPool);
                }
                if(broadcast != null)
                {
                    if(broadcast.IsCompleted)
                    {
                        broadcast = Task.Run(BroadcastBlockchain);
                    }
                }
                else
                {
                    broadcast = Task.Run(BroadcastBlockchain);
                }
                if(peerListBroadcast != null)
                {
                    if(peerListBroadcast.IsCompleted)
                    {
                        peerListBroadcast = Task.Run(BroadcastPeerList);
                    }
                }
                else
                {
                    peerListBroadcast = Task.Run(BroadcastPeerList);
                }
            }
            catch 
            {
                return;
            }
        }
        static async Task CheckForBlocks()
        {
            while(headerFileOpen)
                await Task.Delay(10);
            headerFileOpen = true;
            byte[] bytesBlockHeaders = await File.ReadAllBytesAsync(blockHeadersLocation);
            headerFileOpen = false;
            List<BlockHeader> blockHeaders = MessagePackSerializer.Deserialize<List<BlockHeader>>(bytesBlockHeaders);
            byte[] request;
            if(Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length > 0)
            {
                List<string> hashArray = new List<string>();
                for (int i = 0; i < blockHeaders.Count; i++)
                {
                    string hash = ComputeSHA256Hash(blockHeaders[i].merkleRootHash + blockHeaders[i].previousHash + blockHeaders[i].time + blockHeaders[i].nonce);
                    hashArray.Add(hash);
                }
                request = MessagePackSerializer.Serialize(hashArray);
            }
            else
                return;
            for (int peer = 0; peer < peerList.Count; peer++)
            {
                if(peerList[peer].communicationTimer.Elapsed.Minutes >= 10)
                    continue;
                Block responseAsBlock = new Block();
                // Connect to the server
                using (TcpClient client = new TcpClient())
                {
                    Task connect = client.ConnectAsync(peerList[peer].peerAddress, 012009);
                    Task timeout = Task.Delay(TimeSpan.FromSeconds(0.25f));
                    if(await Task.WhenAny(connect, timeout) == timeout)
                        continue;

                    if (client != null && client.Client != null && client.Client.Connected)
                    {
                        if (client.Client.Poll(5000, SelectMode.SelectWrite))
                        {
                            client.ReceiveTimeout = 100;
                            client.SendTimeout = 100;

                            NetworkStream stream = client.GetStream();

                            // Send a request to the server
                            await stream.WriteAsync(request, 0, request.Length);
                            Stopwatch stopwatch = new Stopwatch();
                            stopwatch.Start();
                            while(!stream.DataAvailable)
                                if(stopwatch.Elapsed > TimeSpan.FromSeconds(3))
                                    break;
                            if(stopwatch.Elapsed > TimeSpan.FromSeconds(3))
                                continue;
                            using (stream)
                            {
                                using (MemoryStream memoryStream = new MemoryStream())
                                {
                                    byte[] buffer = new byte[32768];
                                    int bytesRead;
                                    // Read data in chunks until the server closes the connection
                                    Stopwatch bytesReadTimer = new Stopwatch();
                                    stopwatch.Restart();
                                    bytesReadTimer.Start();
                                    while (stopwatch.Elapsed < TimeSpan.FromSeconds(60))
                                    {
                                        if(bytesReadTimer.Elapsed > TimeSpan.FromSeconds(0.25f))
                                            break;
                                        try
                                        {
                                            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(0.25f)))
                                            {
                                                bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                                                if (bytesRead > 0)
                                                {
                                                    await memoryStream.WriteAsync(buffer, 0, bytesRead);
                                                    bytesReadTimer.Restart();
                                                }
                                            }
                                        }
                                        catch (OperationCanceledException){break;}
                                        catch{break;}
                                    }
                                    stopwatch.Stop();
                                    byte[] allData = memoryStream.ToArray();
                                    if(allData.Length == 0)
                                        continue;
                                    byte[] bytesLastBlock = await File.ReadAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length - 1}.dat");
                                    Block lastBlock = MessagePackSerializer.Deserialize<Block>(bytesLastBlock);
                                    try
                                    {
                                        Tuple<List<BlockHeader>, Block> responseChain = MessagePackSerializer.Deserialize<Tuple<List<BlockHeader>, Block>>(allData);
                                        if(Directory.GetFiles($"{AppContext.BaseDirectory}blocks").Length - responseChain.Item2.blockCount > blockHeaders.Count + 1)
                                            continue;
                                        if(ValidateHeaderChain(responseChain.Item2, responseChain.Item1, blockHeaders))
                                            responseAsBlock = responseChain.Item2;
                                        else
                                            continue;
                                        List<BlockHeader> headersToRemove = new List<BlockHeader>();
                                        byte[] bytesUTXOSet = File.ReadAllBytes(UTXOSetLocation);
                                        List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
                                        List<BroadcastTransaction> utxosToRemove = new List<BroadcastTransaction>();
                                        for (int i = responseAsBlock.blockCount; i < blockHeaders.Count; i++)
                                        {
                                            for (int txI = 0; txI < UTXOSet.Count; txI++)
                                                if(UTXOSet[txI].setBlockTag == i)
                                                    if(!utxosToRemove.Contains(UTXOSet[txI]))
                                                        utxosToRemove.Add(UTXOSet[txI]);
                                            headersToRemove.Add(blockHeaders[i]);
                                            if(i > responseAsBlock.blockCount)
                                                File.Delete($"{AppContext.BaseDirectory}blocks\\block{i}.dat");
                                        }
                                        for (int i = 0; i < utxosToRemove.Count; i++)
                                            UTXOSet.Remove(utxosToRemove[i]);
                                        bytesUTXOSet = MessagePackSerializer.Serialize(UTXOSet);
                                        await File.WriteAllBytesAsync(UTXOSetLocation, bytesUTXOSet);
                                        for (int i = 0; i < headersToRemove.Count; i++)
                                            blockHeaders.Remove(headersToRemove[i]);
                                    }
                                    catch 
                                    {
                                        responseAsBlock = MessagePackSerializer.Deserialize<Block>(allData) ?? null;
                                        if(responseAsBlock.blockHeader.previousHash != lastBlock.hash)
                                            continue;
                                    }
                                    if(Encoding.UTF8.GetByteCount(responseAsBlock.ToString()) > 1048576)
                                        continue;
                                }
                            }
                        }
                    }
                }
                byte[] bytesPreviousBlock = await File.ReadAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{responseAsBlock.blockCount - 1}.dat");
                Block previousBlock = MessagePackSerializer.Deserialize<Block>(bytesPreviousBlock);
                bool isValid = ValidateBlock(previousBlock, responseAsBlock, blockHeaders);
                peerList[peer].communicationTimer.Restart();
                if(isValid)
                {
                    bool continueLoop = false;
                    foreach (BlockHeader header in blockHeaders)
                        if(header == responseAsBlock.blockHeader)
                            continueLoop = true;
                    if(continueLoop)
                        continue;
                    byte[] bytesUTXOSet = await File.ReadAllBytesAsync(UTXOSetLocation);
                    List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
                    blockHeaders.Add(responseAsBlock.blockHeader);
                    bytesBlockHeaders = MessagePackSerializer.Serialize(blockHeaders);
                    await File.WriteAllBytesAsync($"{AppContext.BaseDirectory}blocks\\block{responseAsBlock.blockCount}.dat", MessagePackSerializer.Serialize(responseAsBlock));
                    await File.WriteAllBytesAsync(UTXOSetLocation, MessagePackSerializer.Serialize(UTXOSet));
                    while(headerFileOpen)
                        await Task.Delay(10);
                    headerFileOpen = true;
                    await File.WriteAllBytesAsync(blockHeadersLocation, bytesBlockHeaders);
                    headerFileOpen = false;
                    if (isValidating)
                    {
                        generatingBlock.Cancel();
                        await Task.Delay(100);
                        generatingBlock = new CancellationTokenSource();
                        if(generatingBlockTask.IsCompleted)
                            generatingBlockTask = Task.Run(async() => {await Task.Delay(1000); GenerateBlock(generatingBlock.Token);});
                        Console.WriteLine($"Valid block received from: {peerList[peer].peerAddress}");
                    }
                }
                else
                {
                    if(isValidating)
                        Console.WriteLine($"Invalid block received from: {peerList[peer].peerAddress}, blocking node.");
                    byte[] bytesBlockedPeers = await File.ReadAllBytesAsync(blockedPeersLocation);
                    peerList.Remove(peerList[peer]);
                    if(bytesBlockedPeers.Length != 0)
                    {
                        List<string> blockedPeers = MessagePackSerializer.Deserialize<List<string>>(bytesBlockedPeers);
                        blockedPeers.Add(peerList[peer].peerAddress);
                        peerList.Remove(peerList[peer]);
                        await File.WriteAllBytesAsync(blockedPeersLocation, MessagePackSerializer.Serialize(blockedPeers));
                    }
                    else
                    {
                        List<string> blockedPeers = new List<string>{peerList[peer].peerAddress};
                        await File.WriteAllBytesAsync(blockedPeersLocation, MessagePackSerializer.Serialize(blockedPeers));
                    }
                    List<string> peers = peerList.Select(item => item.peerAddress).ToList();
                    await File.WriteAllBytesAsync(peersLocation, MessagePackSerializer.Serialize(peers));
                }
            }
        }
        static async Task CheckForPeers()
        {
            for (int peer = 0; peer < peerList.Count; peer++)
            {
                if(peerList[peer].communicationTimer.Elapsed.Minutes >= 10)
                    continue;
                // Connect to the server
                using (TcpClient client = new TcpClient())
                {
                    Task connect = client.ConnectAsync(peerList[peer].peerAddress, 012009);
                    Task timeout = Task.Delay(TimeSpan.FromSeconds(1));
                    if(await Task.WhenAny(connect, timeout) == timeout)
                        continue;

                    if (client != null && client.Client != null && client.Client.Connected)
                    {
                        if (client.Client.Poll(5000, SelectMode.SelectWrite))
                        {
                            byte[] buff = new byte[1];

                            client.ReceiveTimeout = 100;
                            client.SendTimeout = 100;

                            NetworkStream stream = client.GetStream();

                            // Send a request to the server
                            string request = "Requesting Peer List";
                            byte[] requestBytes = Encoding.UTF8.GetBytes(request);
                            await stream.WriteAsync(requestBytes, 0, requestBytes.Length);
                            byte[] bytes;
                            using (var memoryStream = new MemoryStream())
                            {
                                Task copy = stream.CopyToAsync(memoryStream);
                                Task timeoutCopy = Task.Delay(TimeSpan.FromSeconds(3));
                                if(await Task.WhenAny(copy, timeoutCopy) == timeoutCopy)
                                    continue;
                                bytes = memoryStream.ToArray();
                            }
                            if(bytes.Length == 0)
                                continue;
                            List<string> receivedList = MessagePackSerializer.Deserialize<List<string>>(bytes);
                            if(receivedList == null)
                                continue;
                            IPAddress[] addresses = await Dns.GetHostAddressesAsync(Dns.GetHostName()) ?? null;
                            string ipv4Address = "";
                            foreach (IPAddress address in addresses)
                                if(address.AddressFamily == AddressFamily.InterNetwork)
                                    ipv4Address = address.ToString();
                            if(ipv4Address == "")
                                continue;
                            byte[] bytesBlockedPeers = await File.ReadAllBytesAsync(blockedPeersLocation);
                            List<string> blockedPeers = new List<string>();
                            if(bytesBlockedPeers.Length != 0)
                                blockedPeers = MessagePackSerializer.Deserialize<List<string>>(bytesBlockedPeers);

                            List<string> peers = peerList.Select(item => item.peerAddress).ToList();
                            foreach (string receivedPeer in receivedList)
                            {
                                if(!peers.Contains(receivedPeer))
                                    if(receivedPeer != ipv4Address && !blockedPeers.Contains(receivedPeer))
                                    {
                                        Peer newPeer = new Peer(receivedPeer);
                                        newPeer.communicationTimer.Start();
                                        peerList.Add(newPeer);
                                        peers.Add(receivedPeer);
                                    }
                            }
                            byte[] bytesPeers = MessagePackSerializer.Serialize(peers);
                            await File.WriteAllBytesAsync(peersLocation, bytesPeers);
                            peerList[peer].communicationTimer.Restart();
                        }
                    }
                }
            }
        }
        static async Task UpdateMemoryPool()
        {
            // Asynchronously accept a client connection
            TcpClient client;
            Task<TcpClient> connect = listener.AcceptTcpClientAsync();
            Task timeout = Task.Delay(TimeSpan.FromSeconds(1));
            if(await Task.WhenAny(connect, timeout) == timeout)
                return;
            else
                client = await connect;
            if(client.Connected)
            {
                await HandleTransaction(client);
            }
        }
        static async Task HandleTransaction(TcpClient client)
        {
            using (client)
            {
                using (NetworkStream stream = client.GetStream())
                {
                    client.ReceiveTimeout = 100;
                    client.SendTimeout = 100;

                    byte[] buffer = new byte[32768];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    string request = "";
                    request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    if (request == "Send Transaction")
                    {
                        byte[] responseBytes = Encoding.UTF8.GetBytes("Accept Transaction");
                        await stream.WriteAsync(responseBytes, 0, responseBytes.Length);

                        byte[] bytes;
                        using (var memoryStream = new MemoryStream())
                        {
                            Task copy = stream.CopyToAsync(memoryStream);
                            Task timeoutCopy = Task.Delay(TimeSpan.FromSeconds(3));
                            if(await Task.WhenAny(copy, timeoutCopy) == timeoutCopy)
                                return;
                            bytes = memoryStream.ToArray();
                        }
                        if (bytes.Length == 0)
                            return;
                        List<string> peers = peerList.Select(item => item.peerAddress).ToList();
                        string peer = (client.Client.RemoteEndPoint as IPEndPoint).ToString().Split(":")[0];
                        if(!peers.Contains(peer))
                        {
                            peers.Add(peer);
                            Peer newPeer = new Peer(peer);
                            newPeer.communicationTimer.Start();
                            peerList.Add(newPeer);
                            peers.Add(peer);
                            byte[] bytesPeers = MessagePackSerializer.Serialize(peers);
                            await File.WriteAllBytesAsync(peersLocation, bytesPeers);
                        }
                        BroadcastTransaction broadcast = MessagePackSerializer.Deserialize<BroadcastTransaction>(bytes);
                        using (ECDsa ecdsa = ECDsa.Create())
                        {
                            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(broadcast.output.senderAddress), out _);
                            if (ecdsa.VerifyData(Encoding.UTF8.GetBytes(broadcast.output.ToString()), Convert.FromBase64String(broadcast.signature), HashAlgorithmName.SHA256))
                            {
                                byte[] bytesUTXOSet = await File.ReadAllBytesAsync(UTXOSetLocation);
                                List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
                                float totalOutput = 0;
                                foreach (BroadcastTransaction transaction in broadcast.unspentOutputs)
                                    totalOutput += transaction.output.sentAmount;

                                if(broadcast.output.sentAmount + broadcast.output.networkFee <= totalOutput)
                                {
                                    bool UTXOsInSet = true;
                                    foreach (BroadcastTransaction UTXO in broadcast.unspentOutputs)
                                    {
                                        if(!UTXOsInSet)
                                            break;
                                        UTXOsInSet = false;
                                        foreach (BroadcastTransaction UTXOInSet in broadcast.unspentOutputs)
                                        {
                                            if(UTXO == UTXOInSet)
                                                UTXOsInSet = true;
                                        }
                                    }
                                    if(UTXOsInSet)
                                    {
                                        if(isValidating)
                                        {
                                            Console.WriteLine("Adding transaction to memory pool:");
                                            Console.WriteLine("{");
                                            Console.WriteLine($"  Sender address: {broadcast.output.senderAddress}");
                                            Console.WriteLine($"  Amount: {broadcast.output.sentAmount}");
                                            Console.WriteLine($"  Receiver address: {broadcast.output.receiverAddress}");
                                            Console.WriteLine("}");
                                        }
                                        memoryPool.Add(broadcast);
                                        peerList[peers.IndexOf(peer)].communicationTimer.Restart();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        static float CheckAddressFunds(List<BroadcastTransaction> UTXOSet, string address)
        {
            float addressfunds = 0;
            foreach (BroadcastTransaction transaction in UTXOSet)
                if(transaction.output.receiverAddress == address)
                    addressfunds += transaction.output.sentAmount;
            return addressfunds;
        }
        static bool CheckForDoubleSpends(List<BroadcastTransaction> transactions)
        {
            List<BroadcastTransaction> outputs = new List<BroadcastTransaction>();
            foreach (BroadcastTransaction transaction in transactions)
            {
                foreach (BroadcastTransaction output in transaction.unspentOutputs)
                {
                    outputs.Add(output);
                }
            }
            for (int i = 0; i < outputs.Count; i++)
            {
                for (int i2 = 0; i2 < outputs.Count; i2++)
                {
                    if(i2 != i)
                        if(outputs[i].transactionID == outputs[i2].transactionID)
                            return false;
                }
            }
            return true;
        }
        static void RemoveDoubleSpends(List<BroadcastTransaction> transactions)
        {
            List<Tuple<BroadcastTransaction, BroadcastTransaction>> outputsWithParentTx = new List<Tuple<BroadcastTransaction, BroadcastTransaction>>();
            foreach (BroadcastTransaction transaction in transactions)
            {
                foreach (BroadcastTransaction output in transaction.unspentOutputs)
                {
                    outputsWithParentTx.Add(new Tuple<BroadcastTransaction, BroadcastTransaction>(output, transaction));
                }
            }
            for (int i = 0; i < outputsWithParentTx.Count; i++)
            {
                for (int i2 = 0; i2 < outputsWithParentTx.Count; i2++)
                {
                    if(i2 != i)
                        if(outputsWithParentTx[i].Item1 == outputsWithParentTx[i2].Item1)
                            transactions.Remove(outputsWithParentTx[i].Item2);
                }
            }
        }
        static void PrintBlockData(Block block)
        {
            List<BroadcastTransaction> transactions = TransactionsFromMerkleTree(block.merkleRoot);
            if(block.blockHeader.previousHash == "")
                Console.WriteLine($"Genesis Block:");
            else    
                Console.WriteLine($"Block {block.blockCount}:");
            Console.WriteLine("{");
            Console.WriteLine($"  Nonce: {block.blockHeader.nonce}");
            Console.WriteLine($"  Difficulty: {block.blockHeader.blockDifficulty:G}Lz");
            Console.WriteLine($"  Hash: {block.hash}");
            if(block.blockHeader.previousHash != "")
                Console.WriteLine($"  Previous Hash: {block.blockHeader.previousHash}");
            Console.WriteLine($"  Time: {DateTimeOffset.FromUnixTimeSeconds(block.blockHeader.time).UtcDateTime:HH:mm:ss, MMMM d, yyyy}");
            Console.WriteLine($"  Transactions: {transactions.Count}");
            float nexusTransacted = 0;
            float blockFees = 0;
            foreach(BroadcastTransaction transaction in transactions)
            {
                nexusTransacted += transaction.output.sentAmount;
                blockFees += transaction.output.networkFee;
            }
            Console.WriteLine($"  Value of transactions: {nexusTransacted:G} nexus");
            Console.WriteLine($"  Block fees: {blockFees:G} nexus");
            Console.WriteLine($"  Block reward: 1 nexus");
            Console.WriteLine($"  Miner: {blockReceivedMiner}");
            Console.WriteLine("}");
        }
        static float GetDifficultyLevel(BlockHeader lastBlock, List<BlockHeader> headers)
        {
            float blockDifficulty = lastBlock.blockDifficulty;
            if(headers.Count % 100 == 0)
            {
                float blockTimeSum = 0;
                for (int i = headers.Count - 98; i < headers.Count; i++)
                {
                    blockTimeSum += headers[i].time -headers[i - 1].time;
                }
                //adjust difficulty level
                blockDifficulty += (float)Math.Log2(12000 / blockTimeSum);
            }
            return blockDifficulty;
        }
        static bool ValidateHeaderChain(Block block, List<BlockHeader> headers, List<BlockHeader> currentHeaders)
        {
            List<BlockHeader> collaterizedHeaders = new List<BlockHeader>(currentHeaders){block.blockHeader};
            foreach (BlockHeader header in headers)
                collaterizedHeaders.Add(header);
            for (int i = 0; i < headers.Count; i++)
            {
                if(i == 0)
                    if(headers[i].previousHash != block.hash)
                        return false;
                string rawData = "";
                if(i > 0)
                    rawData = headers[i].merkleRootHash + headers[i].previousHash + headers[i].time + headers[i].nonce;
                else
                    rawData = headers[i].merkleRootHash + block.hash + headers[i].time + headers[i].nonce;

                using (SHA256 sha256 = SHA256.Create())
                {
                    // Convert the input string to a byte array
                    byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                    string binaryString = string.Join(" ", bytes.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0'))).Replace(" ", "");
                    float difficultyLevel;
                    if(i == 0)
                        difficultyLevel = GetDifficultyLevel(block.blockHeader, collaterizedHeaders.GetRange(0, block.blockCount + 1));
                    else
                        difficultyLevel = GetDifficultyLevel(headers[i - 1], collaterizedHeaders.GetRange(0, block.blockCount + i + 1));
                    if(binaryString.TakeWhile(c => c == '0').Count() < difficultyLevel)
                        return false;
                }
            }
            return true;
        }
        static bool ValidateBlock(Block previousBlock, Block receivedBlock, List<BlockHeader> blockHeaders)
        {
            byte[] bytesUTXOSet = File.ReadAllBytes(UTXOSetLocation);
            List<BroadcastTransaction> UTXOSet = MessagePackSerializer.Deserialize<List<BroadcastTransaction>>(bytesUTXOSet);
            List<BroadcastTransaction> transactions = TransactionsFromMerkleTree(receivedBlock.merkleRoot);
            if(receivedBlock.blockHeader.merkleRootHash != receivedBlock.merkleRoot.hash)
                return false;
            if(receivedBlock.blockCount != previousBlock.blockCount + 1)
            if(!CheckMerkleTreeValidity(receivedBlock.merkleRoot))
                return false;
            float blockDifficulty = GetDifficultyLevel(previousBlock.blockHeader, blockHeaders.GetRange(0, receivedBlock.blockCount));
            string rawData = receivedBlock.blockHeader.merkleRootHash + previousBlock.hash + receivedBlock.blockHeader.time + receivedBlock.blockHeader.nonce;
            if(receivedBlock.hash != ComputeSHA256Hash(rawData))
                return false;
            string binaryString = "";
            using (SHA256 sha256 = SHA256.Create())
            {
                // Convert the input string to a byte array
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                binaryString = string.Join(" ", bytes.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0'))).Replace(" ", "");
            }
            if(binaryString.TakeWhile(c => c == '0').Count() < blockDifficulty)
                return false;

            if(receivedBlock.blockHeader.time < previousBlock.blockHeader.time)
                return false;
                
            if(receivedBlock.blockHeader.time > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 7200)
                return false;

            if(receivedBlock.timeBetweenLastBlock != receivedBlock.blockHeader.time - previousBlock.blockHeader.time)
                return false;
                
            if(!CheckForDoubleSpends(transactions))
            {
                return false;
            }
            List<BroadcastTransaction> utxosToRemove = new List<BroadcastTransaction>();
            List<BroadcastTransaction> utxosToAdd = new List<BroadcastTransaction>();
            float aggregateNetworkFees = 0;
            BroadcastTransaction blockReward = null;
            BroadcastTransaction networkFees = null;
            for(int i = 0; i < transactions.Count; i++)
            {
                if (transactions[i].output.senderAddress == "blockReward")
                {
                    if(transactions[i].transactionID != ComputeSHA256Hash(transactions[i].output.ToString() + receivedBlock.blockCount))
                        return false;
                    blockReward = transactions[i];
                }
                else if (transactions[i].output.senderAddress == "networkFees")
                {
                    if(transactions[i].transactionID != ComputeSHA256Hash(transactions[i].output.ToString() + receivedBlock.blockCount))
                        return false;
                    networkFees = transactions[i];
                }
                else
                {
                    if(transactions[i].transactionID != ComputeSHA256Hash(transactions[i].output.ToString() + transactions[i].unspentOutputs.ToString()))
                        return false;
                    float totalOutput = 0;
                    foreach (BroadcastTransaction transaction in transactions[i].unspentOutputs)
                        totalOutput += transaction.output.sentAmount;
                        
                    if(transactions[i].output.sentAmount + transactions[i].output.networkFee > totalOutput)
                        return false;
                    
                    bool UTXOsInSet = true;
                    for (int tx = 0; tx < transactions[i].unspentOutputs.Count; tx++)
                    {
                        if(!UTXOsInSet)
                            return false;
                        UTXOsInSet = false;
                        utxosToRemove.Add(transactions[i].unspentOutputs[tx]);
                        foreach (BroadcastTransaction UTXOInSet in UTXOSet)
                        {
                            if(transactions[i].unspentOutputs[tx].transactionID == UTXOInSet.transactionID)
                            {
                                UTXOsInSet = true;
                                break;
                            }
                        }
                    }
                    float change = totalOutput - (transactions[i].output.sentAmount + transactions[i].output.networkFee);
                    Transaction networkChangeTransaction = new Transaction(change, 0, transactions[i].output.senderAddress, "networkChange");
                    BroadcastTransaction networkChange = new BroadcastTransaction(networkChangeTransaction, "networkChange", ComputeSHA256Hash(networkChangeTransaction.ToString() + receivedBlock.blockCount));
                    networkChange.setBlockTag = receivedBlock.blockCount;
                    utxosToAdd.Add(networkChange);
                    aggregateNetworkFees += transactions[i].output.networkFee;
                    using (ECDsa ecdsa = ECDsa.Create())
                    {
                        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(transactions[i].output.senderAddress), out _);
                        if(!ecdsa.VerifyData(Encoding.UTF8.GetBytes(transactions[i].output.ToString()), Convert.FromBase64String(transactions[i].signature), HashAlgorithmName.SHA256))
                        {
                            return false;
                        }
                    }
                    transactions[i].setBlockTag = receivedBlock.blockCount;
                    utxosToAdd.Add(transactions[i]);
                }
            }
            if(networkFees == null || blockReward == null)
                return false;
            if (networkFees.output.sentAmount > aggregateNetworkFees || blockReward.output.sentAmount > 1)
                return false;

            blockReward.setBlockTag = receivedBlock.blockCount;
            UTXOSet.Add(blockReward);
            networkFees.setBlockTag = receivedBlock.blockCount;
            if(aggregateNetworkFees > 0)
                UTXOSet.Add(networkFees);
            for (int i = 0; i < utxosToRemove.Count; i++)
                for (int i2 = 0; i2 < UTXOSet.Count; i2++)
                    if(UTXOSet[i2].transactionID == utxosToRemove[i].transactionID)
                        UTXOSet.RemoveAt(i2);
            for (int i = 0; i < utxosToAdd.Count; i++)
                UTXOSet.Add(utxosToAdd[i]);
            for (int i = 0; i < transactions.Count; i++)
                for (int i2 = 0; i2 < memoryPool.Count; i2++)
                    if(memoryPool[i2].transactionID == transactions[i].transactionID)
                        memoryPool.RemoveAt(i2);
            bytesUTXOSet = MessagePackSerializer.Serialize(UTXOSet);
            File.WriteAllBytes(UTXOSetLocation, bytesUTXOSet);
            return true;
        }
        static void GenerateAddresses()
        {
            // 1. Generate ECDSA key pair
            using (ECDsa ecdsa = ECDsa.Create())
            {
                // Export keys
                string publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
                string privateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());

                Console.WriteLine("Public Key:\n" + publicKey);
                Console.WriteLine("\nPrivate Key:\n" + privateKey);

                var bytesStringPublic = MessagePackSerializer.Serialize(publicKey);
                string filePathPublic = publicAddressLocation;

                var bytesStringPrivate = MessagePackSerializer.Serialize(privateKey);
                string filePathPrivate = privateAddressLocation;
                
                File.WriteAllBytes(filePathPublic, bytesStringPublic);
                File.WriteAllBytes(filePathPrivate, bytesStringPrivate);
            }
            Console.ReadLine();
            Task.Run(Menu);
        }
        static void Addresses()
        {
            Console.WriteLine("1: Address List");
            Console.WriteLine("2: Add Address");
            
            string input = Console.ReadLine();
            if (input == "1")
            {
                byte[] bytesPublicAddress = File.ReadAllBytes(publicAddressLocation);
                string publicAddress = MessagePackSerializer.Deserialize<string>(bytesPublicAddress);
                byte[] bytesPrivateAddress = File.ReadAllBytes(privateAddressLocation);
                string privateAddress = MessagePackSerializer.Deserialize<string>(bytesPrivateAddress);

                Console.WriteLine("My Address:");
                Console.WriteLine("{");
                Console.WriteLine($"  Public: {publicAddress}");
                Console.WriteLine();
                Console.WriteLine($"  Private: {privateAddress}");
                Console.WriteLine("}");
                byte[] bytesAddresses = File.ReadAllBytes(addressesLocation);
                if(bytesAddresses.Length != 0)
                {
                    List<string> addresses = MessagePackSerializer.Deserialize<List<string>>(bytesAddresses);
                    Console.WriteLine("Other Addresses:");
                    Console.WriteLine("{");
                    for (int i = 0; i < addresses.Count; i++)
                    {
                        Console.WriteLine($"  {addresses[i]}");
                        if (i != addresses.Count - 1)
                            Console.WriteLine();
                    }
                    Console.WriteLine("}");
                }
                Console.ReadKey();
            }
            else if (input == "2")
            {
                Console.WriteLine("New Address:");
                string newAddress = Console.ReadLine();
                byte[] bytesAddresses = File.ReadAllBytes(addressesLocation);
                if(bytesAddresses.Length != 0)
                {
                    List<string> addresses = MessagePackSerializer.Deserialize<List<string>>(bytesAddresses);
                    File.WriteAllBytesAsync(addressesLocation, MessagePackSerializer.Serialize(addresses));
                }
                else
                {
                    List<string> addresses = new List<string>(){newAddress};
                    File.WriteAllBytesAsync(addressesLocation, MessagePackSerializer.Serialize(addresses));
                }
            }
            else
            {
                Task.Run(Menu);
                return;
            }
            Task.Run(Menu);
        }
        static string ComputeSHA256Hash(string rawData)
        {
            // Create a SHA256 instance
            using (SHA256 sha256 = SHA256.Create())
            {
                // Convert the input string to a byte array
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a hex string
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }
        static void ExitWithInput(object source, ElapsedEventArgs e)
        {
            if (isValidating)
            {
                if(Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true).Key;
                    if (key == ConsoleKey.Enter)
                    {
                        generatingBlock.Cancel();
                        Task.Run(Menu);
                    }
                }
            }
        }
    }
}