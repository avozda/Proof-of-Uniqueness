import { Web3 } from "web3";
import * as fs from "fs";
import * as path from "path";
import { Merkletree, InMemoryDB, Hash } from "@iden3/js-merkletree";
const snarkjs = require("snarkjs");

// Web3 types
interface EventLog {
  event?: string;
  blockNumber: bigint;
  transactionHash: string;
  returnValues: any;
}

// Configuration interface
interface Config {
  RPC_URL: string;
  CONTRACT_ADDRESS: string;
  START_BLOCK: string | number;
}

// Event data interfaces
interface EventData {
  timestamp: string;
  blockNumber: number;
  transactionHash: string;
  event: string;
  data: any;
}

interface HashIDClaimEventData {
  _pA: [string, string];
  _pB: [[string, string], [string, string]];
  _pC: [string, string];
  _pubSignals: [string];
}

interface HashIDInsertedEventData {
  hashID: string;
  newRoot: string;
}

// Configuration - Update these values according to your setup
const CONFIG: Config = {
  RPC_URL: process.env.RPC_URL || "http://localhost:8545",
  CONTRACT_ADDRESS:
    process.env.CONTRACT_ADDRESS ||
    "0x5FbDB2315678afecb367f032d93F642f64180aa3", // Replace with actual contract address
  START_BLOCK: process.env.START_BLOCK || 0,
};

// Load contract ABI
const contractAbiPath = path.join(
  __dirname,
  "../abi/IdentityVerification.json"
);
const contractData = JSON.parse(fs.readFileSync(contractAbiPath, "utf8"));
const contractAbi = contractData.abi;

// SMT and ZK Proof Manager
class SMTManager {
  private smt: Merkletree;
  private wasmPath: string;
  private zkeyPath: string;

  constructor() {
    // Initialize SMT with depth 254 (as used in the circuit)
    const prefix = new Uint8Array([0, 1, 2, 3]); // Some prefix for the DB
    const db = new InMemoryDB(prefix);
    this.smt = new Merkletree(db, true, 254);

    // Paths to ZK assets
    this.wasmPath = path.join(__dirname, "../zk/SMTVerification.wasm");
    this.zkeyPath = path.join(__dirname, "../zk/SMTVerification_final.zkey");
  }

  /**
   * Generate ZK proof for SMT non-membership and insertion
   */
  async generateSMTProof(hashID: string): Promise<any> {
    try {
      console.log(`🔍 Generating SMT proof for hashID: ${hashID}`);

      // Get current SMT root
      const oldRootHash = await this.smt.root();
      const oldRoot = oldRootHash.bigInt().toString();
      console.log(`📊 Current SMT root: ${oldRoot}`);

      // Generate non-membership proof
      const proofResult = await this.smt.generateProof(BigInt(hashID));
      console.log(`🔐 Generated SMT proof for hashID ${hashID}`);

      // Prepare circuit inputs - need exactly 254 siblings for the circuit
      const allSiblings = proofResult.proof.allSiblings();
      const siblings = Array(254).fill("0"); // Initialize with zeros

      // Fill in the actual siblings (should be 254 in total)
      for (let i = 0; i < Math.min(allSiblings.length, 254); i++) {
        const sibling = allSiblings[i];
        if (sibling) {
          siblings[i] = sibling.bigInt().toString();
        }
      }

      // Determine isOld0 and oldKey based on nodeAux
      let isOld0: string;
      let oldKey: string;

      if (proofResult.proof.nodeAux === undefined) {
        // No nodeAux means we're at an empty leaf
        isOld0 = "1";
        oldKey = "0";
        console.log(`📝 Empty leaf case: isOld0=1, oldKey=0`);
      } else {
        // nodeAux exists, meaning there's an existing key at this position
        isOld0 = "0";
        oldKey = proofResult.proof.nodeAux.key.bigInt().toString();
        console.log(`📝 Existing key case: isOld0=0, oldKey=${oldKey}`);
      }

      const circuitInputs = {
        hashID: hashID,
        oldRoot: oldRoot,
        siblings: siblings,
        isOld0: isOld0,
        oldKey: oldKey,
      };

      console.log(`📝 Circuit inputs prepared:`, {
        hashID: circuitInputs.hashID,
        oldRoot: circuitInputs.oldRoot,
        siblingsCount: circuitInputs.siblings.length,
        isOld0: circuitInputs.isOld0,
        oldKey: circuitInputs.oldKey,
      });

      // Dump circuit inputs to JSON file for debugging
      const inputFilePath = path.join(__dirname, "../input.json");
      const circuitInputsForJson = {
        hashID: circuitInputs.hashID.toString(),
        oldRoot: circuitInputs.oldRoot.toString(),
        siblings: circuitInputs.siblings.map((x: any) => x.toString()),
        isOld0: circuitInputs.isOld0.toString(),
        oldKey: circuitInputs.oldKey.toString(),
      };
      fs.writeFileSync(
        inputFilePath,
        JSON.stringify(circuitInputsForJson, null, 2)
      );
      console.log(`📁 Circuit inputs saved to: ${inputFilePath}`);

      // Generate ZK proof
      console.log(`⚡ Generating proof using circuit...`);
      const { proof: zkProof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        this.wasmPath,
        this.zkeyPath
      );

      console.log(`✅ ZK Proof generated successfully!`);
      console.log(`📊 Public signals:`, publicSignals);

      return {
        zkProof,
        publicSignals,
        circuitInputs,
        oldRoot: oldRoot,
      };
    } catch (error) {
      console.error(`❌ Error generating SMT proof:`, error);
      throw error;
    }
  }

  /**
   * Get current SMT root
   */
  async getCurrentRoot(): Promise<string> {
    const rootHash = await this.smt.root();
    return rootHash.bigInt().toString();
  }

  /**
   * Check if hashID exists in SMT
   */
  async containsHashID(hashID: string): Promise<boolean> {
    try {
      const proofResult = await this.smt.generateProof(BigInt(hashID));
      return proofResult.proof.existence;
    } catch (error) {
      console.error(`Error checking hashID existence:`, error);
      return false;
    }
  }

  async addHashIDToTree(hashID: string): Promise<void> {
    try {
      console.log(`🌳 Adding hashID to local tree: ${hashID}`);
      await this.smt.add(BigInt(hashID), BigInt(1));
      const newRoot = await this.smt.root();
      console.log(`✅ Added to tree. New root: ${newRoot.bigInt().toString()}`);
    } catch (error) {
      console.error(`❌ Error adding hashID to tree:`, error);
      throw error;
    }
  }
}

class EventListener {
  private web3: Web3;
  private contract: any;
  private isListening: boolean = false;
  private hashIDClaimSubscription?: any;
  private hashIDInsertedSubscription?: any;
  private lastProcessedBlock: bigint = 0n;
  private pollingInterval?: NodeJS.Timeout | undefined;
  private smtManager: SMTManager;
  private processedTransactions: Set<string> = new Set(); // Track processed transaction hashes

  constructor() {
    this.web3 = new Web3(CONFIG.RPC_URL);
    this.contract = new this.web3.eth.Contract(
      contractAbi,
      CONFIG.CONTRACT_ADDRESS
    );
    this.smtManager = new SMTManager();
  }

  async init(): Promise<boolean> {
    try {
      // Test connection
      const blockNumber = await this.web3.eth.getBlockNumber();
      console.log(`Connected to blockchain. Current block: ${blockNumber}`);
      console.log(`Contract address: ${CONFIG.CONTRACT_ADDRESS}`);
      console.log(`RPC URL: ${CONFIG.RPC_URL}`);
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      console.error("Failed to connect to blockchain:", errorMessage);
      return false;
    }
  }

  private formatEventData(event: EventLog): EventData {
    const timestamp = new Date().toISOString();
    return {
      timestamp,
      blockNumber: Number(event.blockNumber),
      transactionHash: event.transactionHash,
      event: event.event || "",
      data: event.returnValues,
    };
  }

  private handleHashIDClaim(event: EventLog): void {
    const formattedEvent = this.formatEventData(event);
    const data = formattedEvent.data as HashIDClaimEventData;

    // Check if we've already processed this transaction
    if (this.processedTransactions.has(formattedEvent.transactionHash)) {
      console.log(
        `⏭️  Transaction ${formattedEvent.transactionHash} already processed, skipping...`
      );
      return;
    }

    // Mark transaction as processed
    this.processedTransactions.add(formattedEvent.transactionHash);

    console.log("\n🔵 HashIDClaim Event Detected!");
    console.log("================================");
    console.log(`Timestamp: ${formattedEvent.timestamp}`);
    console.log(`Block Number: ${formattedEvent.blockNumber}`);
    console.log(`Transaction Hash: ${formattedEvent.transactionHash}`);
    console.log("Proof Data:");
    console.log(`  pA: [${data._pA[0]}, ${data._pA[1]}]`);
    console.log(
      `  pB: [[${data._pB[0][0]}, ${data._pB[0][1]}], [${data._pB[1][0]}, ${data._pB[1][1]}]]`
    );
    console.log(`  pC: [${data._pC[0]}, ${data._pC[1]}]`);
    console.log(`  Public Signals: [${data._pubSignals[0]}]`);
    console.log("================================");

    // Extract hashID from public signals (the only public signal from hashIDClaim)
    const hashID = data._pubSignals[0];
    console.log(`\n🚀 Starting SMT proof generation for hashID: ${hashID}`);

    // Store original proof data for later submission
    const originalProof = {
      pA: data._pA,
      pB: data._pB,
      pC: data._pC,
      pubSignals: data._pubSignals,
    };

    // Generate ZK proof asynchronously (non-blocking)
    this.generateProofAsync(
      hashID,
      formattedEvent.transactionHash,
      originalProof
    );
  }

  private async generateProofAsync(
    hashID: string,
    txHash: string,
    originalProof: any
  ): Promise<void> {
    try {
      // Check if hashID already exists in SMT
      const exists = await this.smtManager.containsHashID(hashID);
      if (exists) {
        console.log(
          `⚠️  HashID ${hashID} already exists in SMT. Skipping proof generation.`
        );
        return;
      }

      console.log(`⚡ Generating ZK proof for hashID ${hashID} (async)...`);

      // Generate SMT ZK proof
      const smtProofResult = await this.smtManager.generateSMTProof(hashID);

      console.log(
        `\n🎉 SMT ZK Proof Generated Successfully for TX: ${txHash}!`
      );
      console.log("=====================================");
      console.log(`📊 Old Root: ${smtProofResult.oldRoot}`);
      console.log(
        `🔢 Public Signals: [${smtProofResult.publicSignals.join(", ")}]`
      );
      console.log("\n🔐 ZK Proof:");
      console.log(`  π_a: [${smtProofResult.zkProof.pi_a.join(", ")}]`);
      console.log(
        `  π_b: [[${smtProofResult.zkProof.pi_b[0].join(
          ", "
        )}], [${smtProofResult.zkProof.pi_b[1].join(", ")}]]`
      );
      console.log(`  π_c: [${smtProofResult.zkProof.pi_c.join(", ")}]`);
      console.log("\n🔍 Proof Structure Debug:");
      console.log(`  π_a length: ${smtProofResult.zkProof.pi_a.length}`);
      console.log(
        `  π_b length: ${smtProofResult.zkProof.pi_b.length}, inner lengths: [${smtProofResult.zkProof.pi_b[0]?.length}, ${smtProofResult.zkProof.pi_b[1]?.length}]`
      );
      console.log(`  π_c length: ${smtProofResult.zkProof.pi_c.length}`);
      console.log(
        `  publicSignals length: ${smtProofResult.publicSignals.length}`
      );
      console.log("=====================================\n");

      // Now submit both proofs to the smart contract
      await this.submitToSmartContract(
        originalProof,
        smtProofResult,
        hashID,
        txHash
      );
    } catch (error) {
      console.error(
        `❌ Failed to generate SMT proof for hashID ${hashID} (TX: ${txHash}):`,
        error
      );
    }
  }

  private async submitToSmartContract(
    originalProof: any,
    smtProofResult: any,
    hashID: string,
    txHash: string
  ): Promise<void> {
    try {
      console.log(
        `\n🚀 Submitting proofs to smart contract for hashID: ${hashID}`
      );

      // Get current contract root to verify it matches our expected old root
      const contractRoot = await this.contract.methods.root().call();
      console.log(`📊 Current contract root: ${contractRoot}`);
      console.log(`📊 Expected old root: ${smtProofResult.oldRoot}`);

      if (contractRoot.toString() !== smtProofResult.oldRoot.toString()) {
        console.log(
          `⚠️  Contract root mismatch! Expected: ${smtProofResult.oldRoot}, Got: ${contractRoot}`
        );
        console.log(
          `🔄 This might be normal if other transactions were processed first.`
        );
      } else {
        console.log(`✅ Contract root matches expected old root`);
      }

      // Prepare function parameters for insertHashID
      const functionParams = [
        // Original HashIDClaim proof
        originalProof.pA,
        originalProof.pB,
        originalProof.pC,
        originalProof.pubSignals,
        // SMT proof - format for Solidity verifier (strip 3rd coordinate from pi_a and pi_c)
        [smtProofResult.zkProof.pi_a[0], smtProofResult.zkProof.pi_a[1]],
        [
          [
            smtProofResult.zkProof.pi_b[0][1], // Swap coordinates for pi_b
            smtProofResult.zkProof.pi_b[0][0],
          ],
          [
            smtProofResult.zkProof.pi_b[1][1],
            smtProofResult.zkProof.pi_b[1][0],
          ],
        ],
        [smtProofResult.zkProof.pi_c[0], smtProofResult.zkProof.pi_c[1]],
        smtProofResult.publicSignals, // [newRoot, verifiedHashID, publicOldRoot]
      ];

      console.log(`📝 Transaction parameters prepared`);
      console.log(
        `  Original proof signals: [${originalProof.pubSignals.join(", ")}]`
      );
      console.log(
        `  SMT proof signals: [${smtProofResult.publicSignals.join(", ")}]`
      );

      // Get accounts to send transaction
      const accounts = await this.web3.eth.getAccounts();
      if (accounts.length === 0) {
        throw new Error("No accounts available to send transaction");
      }

      const fromAccount = accounts[0];
      console.log(`📤 Sending transaction from account: ${fromAccount}`);

      // Estimate gas
      const gasEstimate = await this.contract.methods
        .insertHashID(...functionParams)
        .estimateGas({ from: fromAccount });

      console.log(`⛽ Estimated gas: ${gasEstimate}`);

      // Send transaction
      const result = await this.contract.methods
        .insertHashID(...functionParams)
        .send({
          from: fromAccount,
          gas: Math.floor(Number(gasEstimate) * 1.2), // Add 20% buffer
        });

      console.log(`\n✅ Transaction submitted successfully!`);
      console.log("=====================================");
      console.log(`📤 Transaction Hash: ${result.transactionHash}`);
      console.log(`📊 Block Number: ${result.blockNumber}`);
      console.log(`⛽ Gas Used: ${result.gasUsed}`);
      console.log(
        `🌳 New Contract Root: ${await this.contract.methods.root().call()}`
      );
      console.log("=====================================\n");
    } catch (error) {
      console.error(
        `❌ Failed to submit transaction for hashID ${hashID} (TX: ${txHash}):`,
        error
      );
    }
  }

  private handleHashIDInserted(event: EventLog): void {
    const formattedEvent = this.formatEventData(event);
    const data = formattedEvent.data as HashIDInsertedEventData;

    console.log("\n🟢 HashIDInserted Event Detected!");
    console.log("==================================");
    console.log(`Timestamp: ${formattedEvent.timestamp}`);
    console.log(`Block Number: ${formattedEvent.blockNumber}`);
    console.log(`Transaction Hash: ${formattedEvent.transactionHash}`);
    console.log(`Hash ID: ${data.hashID}`);
    console.log(`New Root: ${data.newRoot}`);
    console.log("==================================");

    // Update local SMT tree
    this.updateLocalTree(
      data.hashID.toString(),
      formattedEvent.transactionHash
    );
  }

  private async updateLocalTree(hashID: string, txHash: string): Promise<void> {
    try {
      console.log(`🌳 Updating local SMT tree with hashID: ${hashID}`);

      // Check if already exists to avoid duplicate additions
      const exists = await this.smtManager.containsHashID(hashID);
      if (exists) {
        console.log(`⚠️  HashID ${hashID} already exists in local tree`);
        return;
      }

      // Add to local tree
      await this.smtManager.addHashIDToTree(hashID);

      // Check root consistency with smart contract
      await this.checkRootConsistency(txHash);

      console.log(`✅ Local tree updated for TX: ${txHash}\n`);
    } catch (error) {
      console.error(
        `❌ Failed to update local tree for hashID ${hashID} (TX: ${txHash}):`,
        error
      );
    }
  }

  private async checkRootConsistency(txHash: string): Promise<void> {
    try {
      // Get current on-chain root
      const contractRoot = await this.contract.methods.root().call();

      // Get our local tree root
      const localRoot = await this.smtManager.getCurrentRoot();

      if (contractRoot.toString() === localRoot.toString()) {
        console.log(`✅ Root consistency check PASSED for TX: ${txHash}`);
        console.log(`   Contract root: ${contractRoot}`);
        console.log(`   Local root: ${localRoot}`);
      } else {
        console.log(`❌ Root consistency check FAILED for TX: ${txHash}`);
        console.log(`   Contract root: ${contractRoot}`);
        console.log(`   Local root: ${localRoot}`);
      }
    } catch (error) {
      console.error(
        `❌ Failed to check root consistency for TX: ${txHash}:`,
        error
      );
    }
  }

  private async reconstructSMTFromHistory(): Promise<void> {
    try {
      console.log("📚 Fetching all past HashIDInserted events...");

      // Get all HashIDInserted events from the beginning
      const events = await this.contract.getPastEvents("HashIDInserted", {
        fromBlock: CONFIG.START_BLOCK,
        toBlock: "latest",
      });

      console.log(`Found ${events.length} past HashIDInserted events`);

      if (events.length === 0) {
        console.log("✅ No past events found - starting with empty tree");
        return;
      }

      // Sort events by block number to ensure correct order
      events.sort(
        (a: any, b: any) => Number(a.blockNumber) - Number(b.blockNumber)
      );

      console.log("🌳 Rebuilding SMT tree from history...");

      for (const event of events) {
        const data = event.returnValues as any;
        const hashID = data.hashID.toString();

        console.log(`  Adding hashID: ${hashID}`);

        // Add to our local SMT tree
        await this.smtManager.addHashIDToTree(hashID);
      }

      const currentTreeRoot = await this.smtManager.getCurrentRoot();
      console.log(
        `✅ Tree reconstruction complete. Local root: ${currentTreeRoot}`
      );
    } catch (error) {
      console.error("❌ Failed to reconstruct SMT tree:", error);
      throw error;
    }
  }

  private async verifyTreeSync(): Promise<void> {
    try {
      // Get current on-chain root
      const contractRoot = await this.contract.methods.root().call();

      // Get our local tree root
      const localRoot = await this.smtManager.getCurrentRoot();

      console.log(`📊 Contract root: ${contractRoot}`);
      console.log(`🌳 Local tree root: ${localRoot}`);

      if (contractRoot.toString() === localRoot.toString()) {
        console.log(
          "✅ Tree roots match! Local tree is synchronized with on-chain state."
        );
      } else {
        console.log("❌ Tree roots do NOT match!");
        console.log(`   Expected (contract): ${contractRoot}`);
        console.log(`   Actual (local tree): ${localRoot}`);
        throw new Error("Tree synchronization failed - roots do not match");
      }
    } catch (error) {
      console.error("❌ Failed to verify tree synchronization:", error);
      throw error;
    }
  }

  async startListening(): Promise<void> {
    if (this.isListening) {
      console.log("Event listener is already running.");
      return;
    }

    try {
      // Step 1: Reconstruct SMT tree from all past HashIDInserted events
      console.log("\n🔄 Reconstructing SMT tree from past events...");
      await this.reconstructSMTFromHistory();

      // Step 2: Verify tree root matches on-chain root
      console.log("\n🔍 Verifying tree synchronization...");
      await this.verifyTreeSync();

      // Step 3: Start listening for new events
      console.log("\n🎧 Starting to listen for new events...");

      this.isListening = true;

      // Get current block number to start listening from
      const currentBlock = await this.web3.eth.getBlockNumber();
      this.lastProcessedBlock = currentBlock;

      console.log(`Starting from block: ${currentBlock}`);
      console.log("🔍 Will poll for new events every 2 seconds...");

      // Start polling for new events
      this.startPolling();

      console.log("✅ Event listeners are now active!");
      console.log("Waiting for new events... (Press Ctrl+C to stop)\n");
    } catch (error) {
      console.error("Failed to start event listeners:", error);
      this.isListening = false;
    }
  }

  private startPolling(): void {
    this.pollingInterval = setInterval(async () => {
      if (!this.isListening) {
        return;
      }

      try {
        const currentBlock = await this.web3.eth.getBlockNumber();

        // Only check for events if there are new blocks
        if (currentBlock > this.lastProcessedBlock) {
          console.log(
            `🔍 Checking blocks ${
              this.lastProcessedBlock + 1n
            } to ${currentBlock} for new events...`
          );

          await this.checkForNewEvents(
            this.lastProcessedBlock + 1n,
            currentBlock
          );
          this.lastProcessedBlock = currentBlock;
        }
      } catch (error) {
        console.error("Error during polling:", error);
      }
    }, 2000); // Poll every 2 seconds
  }

  private async checkForNewEvents(
    fromBlock: bigint,
    toBlock: bigint
  ): Promise<void> {
    try {
      // Get HashIDClaim events
      const hashIDClaimEvents = await this.contract.getPastEvents(
        "HashIDClaim",
        {
          fromBlock: Number(fromBlock),
          toBlock: Number(toBlock),
        }
      );

      // Get HashIDInserted events
      const hashIDInsertedEvents = await this.contract.getPastEvents(
        "HashIDInserted",
        {
          fromBlock: Number(fromBlock),
          toBlock: Number(toBlock),
        }
      );

      // Combine and sort events by block number
      const allEvents = [
        ...hashIDClaimEvents,
        ...hashIDInsertedEvents,
      ] as EventLog[];
      allEvents.sort((a, b) => Number(a.blockNumber) - Number(b.blockNumber));

      // Process each event
      for (const event of allEvents) {
        if (event.event === "HashIDClaim") {
          this.handleHashIDClaim(event);
        } else if (event.event === "HashIDInserted") {
          this.handleHashIDInserted(event);
        }
      }

      if (allEvents.length > 0) {
        console.log(
          `✨ Processed ${allEvents.length} new events from blocks ${fromBlock} to ${toBlock}\n`
        );
      }
    } catch (error) {
      console.error("Error checking for new events:", error);
    }
  }

  async getPastEvents(
    fromBlock: number | string = 0,
    toBlock: string = "latest"
  ): Promise<void> {
    console.log(
      `\n📜 Fetching past events from block ${fromBlock} to ${toBlock}...`
    );

    try {
      // Get past HashIDClaim events
      const hashIDClaimEvents = await this.contract.getPastEvents(
        "HashIDClaim",
        {
          fromBlock,
          toBlock,
        }
      );

      // Get past HashIDInserted events
      const hashIDInsertedEvents = await this.contract.getPastEvents(
        "HashIDInserted",
        {
          fromBlock,
          toBlock,
        }
      );

      console.log(
        `Found ${hashIDClaimEvents.length} HashIDClaim events and ${hashIDInsertedEvents.length} HashIDInserted events.\n`
      );

      // Print all past events in chronological order
      const allEvents = [
        ...hashIDClaimEvents,
        ...hashIDInsertedEvents,
      ] as EventLog[];
      allEvents.sort((a, b) => Number(a.blockNumber) - Number(b.blockNumber));

      for (const event of allEvents) {
        if (event.event === "HashIDClaim") {
          this.handleHashIDClaim(event);
        } else if (event.event === "HashIDInserted") {
          this.handleHashIDInserted(event);
        }
      }
    } catch (error) {
      console.error("Error fetching past events:", error);
    }
  }

  stop(): void {
    this.isListening = false;
    console.log("\n🛑 Stopping event listeners...");

    // Clean up polling interval
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      delete this.pollingInterval;
    }

    // Clean up subscriptions (if any)
    if (this.hashIDClaimSubscription) {
      this.hashIDClaimSubscription.unsubscribe();
    }
    if (this.hashIDInsertedSubscription) {
      this.hashIDInsertedSubscription.unsubscribe();
    }
  }
}

// Main execution
async function main(): Promise<void> {
  console.log("🚀 Identity Verification Event Listener");
  console.log("=========================================");

  // Validate configuration
  if (
    CONFIG.CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000"
  ) {
    console.log(
      "⚠️  Please update the CONTRACT_ADDRESS in the configuration section of this file or set the CONTRACT_ADDRESS environment variable."
    );
    console.log("Current configuration:");
    console.log(`  RPC_URL: ${CONFIG.RPC_URL}`);
    console.log(`  CONTRACT_ADDRESS: ${CONFIG.CONTRACT_ADDRESS}`);
    console.log(`  START_BLOCK: ${CONFIG.START_BLOCK}`);
    console.log("\nTo set environment variables, you can:");
    console.log(
      "  export CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890"
    );
    console.log(
      "  export RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
    );
    console.log("  export START_BLOCK=18000000");
    console.log("\nOr update the CONFIG object directly in this file.\n");
    process.exit(1);
  }

  const listener = new EventListener();

  // Initialize connection
  const connected = await listener.init();
  if (!connected) {
    console.log(
      "❌ Failed to connect to blockchain. Please check your RPC_URL configuration."
    );
    process.exit(1);
  }

  // Handle graceful shutdown
  process.on("SIGINT", () => {
    console.log("\n\nReceived SIGINT signal. Shutting down gracefully...");
    listener.stop();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    console.log("\n\nReceived SIGTERM signal. Shutting down gracefully...");
    listener.stop();
    process.exit(0);
  });

  // Start listening for new events (includes tree reconstruction)
  await listener.startListening();
}

// Export for potential use as a module
export { EventListener, CONFIG };

// Run if this file is executed directly
if (require.main === module) {
  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
