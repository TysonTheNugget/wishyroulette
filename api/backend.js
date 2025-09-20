require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bip39 = require("bip39");
const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const { createClient } = require("@redis/client");
const rateLimit = require("express-rate-limit");

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);
const app = express();
const port = process.env.PORT || 10000;

app.set("trust proxy", 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const corsOptions = {
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

if (!process.env.MNEMONIC) {
  console.error("Error: MNEMONIC environment variable is not set");
  process.exit(1);
}
if (!process.env.REDIS_URL) {
  console.error("Error: REDIS_URL environment variable is not set");
  process.exit(1);
}

const adminApiKey = process.env.API_KEY;
const networkType = process.env.NETWORK || "testnet"; // Default to testnet for safety
const network =
  networkType === "testnet"
    ? bitcoin.networks.testnet
    : bitcoin.networks.bitcoin;
const mempoolBase =
  networkType === "testnet"
    ? "https://mempool.space/testnet/api"
    : "https://mempool.space/api";
const baseUrl =
  networkType === "testnet"
    ? "https://testnet-api.unisat.io/v1"
    : "https://api.unisat.io/v1";
const ordiscanApiKey =
  process.env.ORDISCAN_API_KEY || "373a1e27-947f-4bd8-80c6-639a03014a16";
const headers = { Authorization: `Bearer ${ordiscanApiKey}` };

const mnemonic = process.env.MNEMONIC;
let seed;
try {
  seed = bip39.mnemonicToSeedSync(mnemonic);
} catch (e) {
  console.error(`Error generating seed from MNEMONIC: ${e.message}`);
  process.exit(1);
}

const root = bip32.fromSeed(seed, network);
const child = root.derivePath("m/84'/0'/0'/0/0");
const { address } = bitcoin.payments.p2wpkh({
  pubkey: Buffer.from(child.publicKey),
  network,
});

const runeName = "WISHYWASHYMACHINE";
let runeId = process.env.RUNE_ID || "865286:2249";
let decimals = Number(process.env.RUNE_DECIMALS ?? 0);

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: { tls: process.env.REDIS_URL.startsWith("rediss://") },
});
redisClient.on("error", (err) => console.error("Redis Client Error", err));

async function connectRedis() {
  if (!redisClient.isOpen) {
    try {
      await redisClient.connect();
      console.log("Redis connected successfully");
    } catch (e) {
      console.error("Redis connection failed:", e.message);
      throw e;
    }
  }
}

async function getState(key, defaultValue) {
  await connectRedis();
  const value = await redisClient.get(key);
  return value ? JSON.parse(value) : defaultValue;
}

async function setState(key, value) {
  await connectRedis();
  await redisClient.set(key, JSON.stringify(value));
}

function authAdmin(req, res, next) {
  if (req.query.api_key !== adminApiKey) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  next();
}

async function init() {
  console.log("Initializing rune info and scanning history...");
  try {
    // Fetch rune info with retry
    let runeFetchAttempts = 0;
    const maxAttempts = 3;
    let runeData = null;
    while (runeFetchAttempts < maxAttempts) {
      try {
        const res = await fetch(`${baseUrl}/rune/${runeName}`, { headers });
        const responseText = await res.text();
        if (!res.ok) {
          console.error(
            `Rune fetch attempt ${runeFetchAttempts + 1} failed: HTTP ${res.status}, Response: ${responseText}`
          );
          runeFetchAttempts++;
          if (runeFetchAttempts === maxAttempts) {
            console.warn("Max rune fetch attempts reached, using defaults");
            break;
          }
          await new Promise(resolve => setTimeout(resolve, 2000));
          continue;
        }
        runeData = JSON.parse(responseText);
        break;
      } catch (e) {
        console.error(`Rune fetch error on attempt ${runeFetchAttempts + 1}: ${e.message}`);
        runeFetchAttempts++;
        if (runeFetchAttempts === maxAttempts) {
          console.warn("Max rune fetch attempts reached, using defaults");
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    if (runeData && typeof runeData.id === "string" && runeData.id.includes(":")) {
      runeId = runeData.id;
    }
    if (Number.isInteger(runeData?.decimals)) {
      decimals = runeData.decimals;
    }
    console.log(`Rune ID: ${runeId}, Decimals: ${decimals}`);

    // Perform historical scan
    await scanHistoricalTransactions();

    return { success: true, runeId, decimals };
  } catch (e) {
    console.error(`Init error: ${e.message}`);
    return { success: false, error: e.message };
  }
}

async function scanHistoricalTransactions() {
  console.log(`Scanning historical transactions for address: ${address}`);
  try {
    let contributors = await getState("contributors", {});
    let gameHistory = await getState("gameHistory", []);
    let lastTxid = await getState("lastTxid", null);
    let scannedHeight = await getState("scannedHeight", 0);

    const currentHeight = await getCurrentHeight();
    if (currentHeight === null) {
      console.error("Failed to get current height for scan");
      return;
    }

    // Fetch transaction history with retry
    let txFetchAttempts = 0;
    const maxAttempts = 3;
    let data = [];
    while (txFetchAttempts < maxAttempts) {
      try {
        const res = await fetch(
          `${baseUrl}/address/${address}/activity/runes?sort=oldest`,
          { headers }
        );
        if (!res.ok) {
          console.error(`Tx history fetch attempt ${txFetchAttempts + 1} failed: HTTP ${res.status}`);
          txFetchAttempts++;
          if (txFetchAttempts === maxAttempts) {
            console.warn("Max tx fetch attempts reached, trying mempool...");
            data = await fetchMempoolHistory();
            break;
          }
          await new Promise(resolve => setTimeout(resolve, 2000));
          continue;
        }
        const response = await res.json();
        data = response.data || [];
        break;
      } catch (e) {
        console.error(`Tx history fetch error on attempt ${txFetchAttempts + 1}: ${e.message}`);
        txFetchAttempts++;
        if (txFetchAttempts === maxAttempts) {
          console.warn("Max tx fetch attempts reached, trying mempool...");
          data = await fetchMempoolHistory();
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    for (const tx of data) {
      if (lastTxid && tx.txid === lastTxid) continue;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let sender = null;
      let recipient = null;

      for (const out of tx.outputs || []) {
        if (out.address === address && out.rune === runeName) {
          incomingAmount += BigInt(out.rune_amount || 0);
        }
        if (out.rune === runeName && out.address !== address) {
          outgoingAmount += BigInt(out.rune_amount || 0);
          recipient = out.address;
        }
      }

      const senders = tx.inputs
        ?.filter((inp) => inp.address && inp.address !== address && inp.rune === runeName)
        .map((inp) => inp.address) || [];

      if (incomingAmount > 0n && senders.length > 0) {
        for (const s of senders) {
          contributors[s] = (
            BigInt(contributors[s] || 0) + incomingAmount
          ).toString();
          console.log(
            `Historical contribution from ${s}: ${incomingAmount.toString()}`
          );
        }
      }

      if (outgoingAmount > 0n && recipient) {
        console.log(
          `Detected historical payout of ${outgoingAmount} to ${recipient}`
        );
        gameHistory.unshift({
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.timestamp || Date.now(),
          txid: tx.txid,
        });
        contributors = {};
        await setState("lastWinner", recipient);
        await setState("lastPayout", {
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.timestamp || Date.now(),
        });
      }
    }

    if (data.length > 0) {
      lastTxid = data[data.length - 1].txid;
      await setState("lastTxid", lastTxid);
      console.log(`Updated lastTxid to ${lastTxid}`);
    }

    await setState("contributors", contributors);
    await setState("gameHistory", gameHistory);
    await setState("scannedHeight", currentHeight);
    console.log("Historical scan completed");
  } catch (e) {
    console.error("Historical scan error:", e);
  }
}

async function fetchMempoolHistory() {
  console.log(`Fetching transaction history from mempool for ${address}`);
  try {
    const res = await fetch(`${mempoolBase}/address/${address}/txs`);
    if (!res.ok) {
      console.error(`Mempool history fetch failed: HTTP ${res.status}`);
      return [];
    }
    const txs = await res.json();
    const runeTxs = [];
    for (const tx of txs) {
      let hasRune = false;
      let outputs = [];
      let inputs = [];
      for (const vout of tx.vout) {
        if (vout.runes?.some((r) => r.rune_name === runeName)) {
          hasRune = true;
          outputs.push({
            address: vout.scriptpubkey_address,
            rune: runeName,
            rune_amount: vout.runes.find((r) => r.rune_name === runeName)?.amount || 0,
          });
        }
      }
      for (const vin of tx.vin) {
        if (vin.prevout?.runes?.some((r) => r.rune_name === runeName)) {
          hasRune = true;
          inputs.push({
            address: vin.prevout.scriptpubkey_address,
            rune: runeName,
          });
        }
      }
      if (hasRune) {
        runeTxs.push({ txid: tx.txid, inputs, outputs, timestamp: tx.status.block_time });
      }
    }
    return runeTxs;
  } catch (e) {
    console.error("Mempool history fetch error:", e);
    return [];
  }
}

async function pollMempool() {
  console.log(`Polling mempool for unconfirmed txs to ${address}`);
  try {
    const res = await fetch(`${mempoolBase}/address/${address}/txs/mempool`);
    if (!res.ok) {
      console.error(`Mempool poll failed: HTTP ${res.status}`);
      return { success: false, error: await res.text(), pending: [] };
    }
    const txs = await res.json();
    let pendingContributions = [];
    for (const tx of txs) {
      const txid = tx.txid;
      let incomingAmount = 0n;
      let sender = null;
      for (const vout of tx.vout) {
        if (vout.scriptpubkey_address === address && vout.runes) {
          const rune = vout.runes.find((r) => r.rune_name === runeName);
          if (rune) incomingAmount += BigInt(rune.amount || 0);
        }
      }
      if (incomingAmount > 0n) {
        for (const vin of tx.vin) {
          if (vin.prevout && vin.prevout.runes) {
            const rune = vin.prevout.runes.find(
              (r) => r.rune_name === runeName
            );
            if (rune && BigInt(rune.amount || 0) > 0n) {
              sender = vin.prevout.scriptpubkey_address;
              break;
            }
          }
        }
        if (sender && sender !== address) {
          const alias = Buffer.from(sender + txid)
            .toString("base64")
            .slice(0, 6)
            .toUpperCase();
          pendingContributions.push({
            sender,
            amount: incomingAmount.toString(),
            txid,
            status: "pending",
            alias,
          });
          console.log(
            `Pending contribution from ${sender}: ${incomingAmount} (txid: ${txid}, alias: ${alias})`
          );
        }
      }
    }
    return { success: true, pending: pendingContributions };
  } catch (e) {
    console.error("Mempool poll error:", e);
    return { success: false, error: e.message, pending: [] };
  }
}

async function pollActivity() {
  console.log(`Polling activity for address: ${address}`);
  try {
    let contributors = await getState("contributors", {});
    let lastTxid = await getState("lastTxid", null);
    let pendingContributors = await getState("pendingContributors", {});
    let gameHistory = await getState("gameHistory", []);

    const pendingResult = await pollMempool();
    if (pendingResult.success) {
      for (const contrib of pendingResult.pending) {
        if (!pendingContributors[contrib.txid]) {
          pendingContributors[contrib.txid] = contrib;
        }
      }
      await setState("pendingContributors", pendingContributors);
    }

    const res = await fetch(
      `${baseUrl}/address/${address}/activity/runes?sort=newest`,
      { headers }
    );
    if (!res.ok) {
      console.error(`Poll failed: HTTP ${res.status}, trying mempool...`);
      const mempoolData = await fetchMempoolHistory();
      if (mempoolData.length > 0) {
        processTransactions(mempoolData, contributors, gameHistory, lastTxid, pendingContributors);
      } else {
        console.error("Mempool fallback also failed");
        return { success: false, error: "Transaction fetch failed" };
      }
    } else {
      const response = await res.json();
      const data = response.data || [];
      processTransactions(data, contributors, gameHistory, lastTxid, pendingContributors);
    }

    await setState("contributors", contributors);
    await setState("gameHistory", gameHistory);
    await setState("pendingContributors", pendingContributors);

    const balanceResult = await getBalance();
    if (balanceResult.success && BigInt(balanceResult.balance) > 0n) {
      console.log(`Balance exists (${balanceResult.balance}), open game detected`);
    }

    return { success: true, newContributions: 0, newWithdrawals: 0 };
  } catch (e) {
    console.error("Poll activity error:", e);
    return { success: false, error: e.message };
  }
}

function processTransactions(data, contributors, gameHistory, lastTxid, pendingContributors) {
  let newContributions = 0;
  let newWithdrawals = 0;
  for (const tx of data) {
    if (lastTxid && tx.txid === lastTxid) continue;

    let incomingAmount = 0n;
    let outgoingAmount = 0n;
    let sender = null;
    let recipient = null;

    for (const out of tx.outputs || []) {
      if (out.address === address && out.rune === runeName) {
        incomingAmount += BigInt(out.rune_amount || 0);
      }
      if (out.rune === runeName && out.address !== address) {
        outgoingAmount += BigInt(out.rune_amount || 0);
        recipient = out.address;
      }
    }

    const senders = tx.inputs
      ?.filter((inp) => inp.address && inp.address !== address && inp.rune === runeName)
      .map((inp) => inp.address) || [];

    if (incomingAmount > 0n && senders.length > 0) {
      for (const s of senders) {
        contributors[s] = (
          BigInt(contributors[s] || 0) + incomingAmount
        ).toString();
        newContributions++;
        console.log(
          `New contribution from ${s}: ${incomingAmount.toString()}`
        );
      }
    }

    if (outgoingAmount > 0n && recipient) {
      console.log(
        `Detected outgoing transfer of ${outgoingAmount} to ${recipient}`
      );
      gameHistory.unshift({
        winner: recipient,
        amount: outgoingAmount.toString(),
        timestamp: tx.timestamp || Date.now(),
        txid: tx.txid,
      });
      contributors = {};
      setState("lastWinner", recipient);
      setState("lastPayout", {
        winner: recipient,
        amount: outgoingAmount.toString(),
        timestamp: tx.timestamp || Date.now(),
      });
      newWithdrawals++;
    }
  }

  if (data.length > 0) {
    lastTxid = data[0].txid;
    setState("lastTxid", lastTxid);
    console.log(`Updated lastTxid to ${lastTxid}`);
  }

  let updatedPending = { ...pendingContributors };
  for (const txid in pendingContributors) {
    if (data.some((tx) => tx.txid === txid)) {
      const pend = pendingContributors[txid];
      contributors[pend.sender] = (
        BigInt(contributors[pend.sender] || 0) + BigInt(pend.amount)
      ).toString();
      delete updatedPending[txid];
    }
  }
  setState("pendingContributors", updatedPending);
}

async function getCurrentHeight() {
  console.log("Fetching current block height...");
  try {
    const res = await fetch(`${mempoolBase}/blocks/tip/height`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const height = Number(await res.text());
    console.log(`Current height: ${height}`);
    return height;
  } catch (e) {
    console.error("Get height error:", e);
    return null;
  }
}

async function checkBlock() {
  console.log("Checking for new block...");
  try {
    let currentHeight = await getState("currentHeight", 0);
    let contributors = await getState("contributors", {});
    let lastWinner = await getState("lastWinner", null);
    let gameHistory = await getState("gameHistory", []);
    const height = await getCurrentHeight();
    if (height === null)
      return { success: false, error: "Failed to get height" };
    if (height > currentHeight && currentHeight > 0) {
      console.log(
        `New block detected: ${height}. Triggering lottery for previous height ${height - 1}`
      );
      const pot = Object.values(contributors).reduce(
        (a, b) => a + BigInt(b),
        0n
      );
      if (pot > 0n) {
        console.log(`Pot value: ${pot.toString()}`);
        const prevHeight = height - 1;
        let hash;
        try {
          const blockRes = await fetch(
            `${mempoolBase}/block-height/${prevHeight}`
          );
          const responseText = await blockRes.text();
          if (!blockRes.ok)
            throw new Error(
              `mempool.space failed: HTTP ${blockRes.status}, ${responseText}`
            );
          hash = responseText.trim();
          console.log(`Using block hash ${hash} for randomness`);
        } catch (e) {
          console.error(`mempool.space error: ${e.message}`);
          return { success: false, error: `Block fetch error: ${e.message}` };
        }
        const rand = BigInt(`0x${hash}`) % pot;
        const entries = Object.entries(contributors).sort((a, b) =>
          a[0].localeCompare(b[0])
        );
        let cum = 0n;
        let winner = null;
        for (const [addr, amtStr] of entries) {
          const amt = BigInt(amtStr);
          if (rand >= cum && rand < cum + amt) {
            winner = addr;
            break;
          }
          cum += amt;
        }
        if (winner) {
          console.log(`Winner selected: ${winner}`);
          const success = await payoutTo(winner);
          if (success) {
            console.log(
              `Payout of ${pot.toString()} WISHY to ${winner} completed`
            );
            gameHistory.unshift({
              winner,
              amount: pot.toString(),
              timestamp: Date.now(),
              txid: null,
            });
            contributors = {};
            lastWinner = winner;
            await setState("contributors", contributors);
            await setState("lastWinner", lastWinner);
            await setState("lastPayout", {
              winner,
              amount: pot.toString(),
              timestamp: Date.now(),
            });
            await setState("gameHistory", gameHistory);
            return { success: true, winner };
          } else {
            return { success: false, error: "Payout failed" };
          }
        } else {
          console.log("No winner selected (edge case)");
          return { success: false, error: "No winner" };
        }
      } else {
        console.log("Pot is empty, no lottery");
        return { success: true, message: "Empty pot" };
      }
    }
    currentHeight = height;
    await setState("currentHeight", currentHeight);
    return { success: true, message: "No action" };
  } catch (e) {
    console.error("Check block error:", e);
    return { success: false, error: e.message };
  }
}

async function payoutTo(winnerAddress) {
  console.log(`Attempting payout to ${winnerAddress}`);
  if (!runeId || !runeId.includes(":")) {
    console.error(`Payout aborted: runeId invalid (${runeId})`);
    return false;
  }
  try {
    const utxoRes = await fetch(`${baseUrl}/address/${address}/utxos`, {
      headers,
    });
    if (!utxoRes.ok) {
      const errorText = await utxoRes.text();
      console.error(`UTXO fetch failed: HTTP ${utxoRes.status}, ${errorText}`);
      return false;
    }
    const utxoResponse = await utxoRes.json();
    const utxos = utxoResponse.data || [];
    if (utxos.length === 0) {
      console.log("No UTXOs");
      return false;
    }
    let totalSats = 0n;
    let hasRune = false;
    let runeAmount = 0n;
    utxos.forEach((u) => {
      totalSats += BigInt(u.value);
      if (u.runes) {
        u.runes.forEach((r) => {
          if (r.name === runeName) {
            hasRune = true;
            runeAmount += BigInt(r.amount);
          }
        });
      }
    });
    console.log(
      `Total sats: ${totalSats}, Has rune: ${hasRune}, Rune amount: ${runeAmount.toString()}`
    );
    if (!hasRune) {
      console.log("No runes found in UTXOs");
      return false;
    }
    const feeRes = await fetch(`${mempoolBase}/v1/fees/recommended`);
    if (!feeRes.ok) {
      const errorText = await feeRes.text();
      console.error(`Fee fetch failed: HTTP ${feeRes.status}, ${errorText}`);
      return false;
    }
    const fees = await feeRes.json();
    const feeRate = fees.economyFee;
    console.log(`Using fee rate: ${feeRate} sat/vB`);
    const txSize = 10 + utxos.length * 68 + 34 * 3 + 20;
    let fee = BigInt(feeRate * txSize);
    const dust = 546n;
    let change = totalSats - dust - fee;
    if (change < 0n) {
      console.log("Insufficient sats for fee");
      return false;
    }
    const psbt = new bitcoin.Psbt({ network });
    const p2wpkh = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(child.publicKey),
      network,
    });
    for (const u of utxos) {
      if (!u.outpoint) {
        console.error(`Invalid UTXO: ${JSON.stringify(u)}`);
        continue;
      }
      const [h, idxStr] = u.outpoint.split(":");
      const script = u.script_pubkey
        ? Buffer.from(u.script_pubkey, "hex")
        : p2wpkh.output;
      psbt.addInput({
        hash: h,
        index: Number(idxStr),
        witnessUtxo: { value: Number(BigInt(u.value)), script },
      });
    }
    psbt.addOutput({ address: winnerAddress, value: Number(dust) });
    let outputIndex = 0;
    if (change >= dust) {
      psbt.addOutput({ address, value: Number(change) });
      outputIndex = 1;
    }
    const [blockStr, txStr] = runeId.split(":");
    const deltaBlock = BigInt(blockStr);
    const deltaTx = BigInt(txStr);
    const amount = runeAmount;
    const payload = Buffer.concat([
      encodeVarint(0n),
      encodeVarint(deltaBlock),
      encodeVarint(deltaTx),
      encodeVarint(amount),
      encodeVarint(BigInt(outputIndex)),
    ]);
    const opReturnScript = bitcoin.script.compile([
      bitcoin.opcodes.OP_RETURN,
      bitcoin.opcodes.OP_13,
      payload,
    ]);
    psbt.addOutput({ script: opReturnScript, value: 0 });
    const signer = {
      publicKey: Buffer.from(child.publicKey),
      sign: (hash) => Buffer.from(child.sign(hash)),
    };
    for (let i = 0; i < utxos.length; i++) {
      psbt.signInput(i, signer);
    }
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();
    console.log(`Built TX: ${txHex}`);
    const broadRes = await fetch(`${mempoolBase}/tx`, {
      method: "POST",
      body: txHex,
    });
    if (broadRes.ok) {
      const txid = await broadRes.text();
      console.log(`Broadcast successful: TXID ${txid}`);
      return true;
    } else {
      const errorText = await broadRes.text();
      console.error(`Broadcast failed: ${errorText}`);
      return false;
    }
  } catch (e) {
    console.error(`Payout error: ${e.message}`);
    return false;
  }
}

async function getBalance() {
  console.log(`Fetching rune balance for address: ${address}`);
  try {
    let res = await fetch(`${baseUrl}/address/${address}/runes`, { headers });
    if (!res.ok) {
      console.warn(`Unisat failed: HTTP ${res.status}, trying mempool...`);
      const mempoolBalance = await getMempoolBalance();
      if (mempoolBalance.success) return mempoolBalance;
      console.error(`Balance fetch failed: HTTP ${res.status}`);
      return { success: false, error: `Unisat failed: HTTP ${res.status}` };
    }
    const response = await res.json();
    const data = response.data || [];
    let balance = 0n;
    for (const rune of data) {
      if (rune.rune_name === runeName) {
        balance = BigInt(rune.amount || 0);
        break;
      }
    }
    console.log(
      `Current rune balance: ${balance.toString()} WISHYWASHYMACHINE`
    );
    return { success: true, balance: balance.toString() };
  } catch (e) {
    console.error(`Balance fetch error: ${e.message}, trying mempool...`);
    const mempoolBalance = await getMempoolBalance();
    if (mempoolBalance.success) return mempoolBalance;
    return { success: false, error: e.message };
  }
}

async function getMempoolBalance() {
  console.log(`Fetching balance from mempool for ${address}`);
  try {
    const res = await fetch(`${mempoolBase}/address/${address}/utxos`);
    if (!res.ok) {
      console.error(`Mempool balance fetch failed: HTTP ${res.status}`);
      return { success: false, error: `Mempool failed: HTTP ${res.status}` };
    }
    const utxos = await res.json();
    let balance = 0n;
    for (const utxo of utxos) {
      if (utxo.runes) {
        const rune = utxo.runes.find((r) => r.rune_name === runeName);
        if (rune) balance += BigInt(rune.amount || 0);
      }
    }
    console.log(`Mempool balance: ${balance.toString()} WISHYWASHYMACHINE`);
    return { success: true, balance: balance.toString() };
  } catch (e) {
    console.error(`Mempool balance fetch error: ${e.message}`);
    return { success: false, error: e.message };
  }
}

async function getHistory() {
  console.log("Fetching game history...");
  try {
    const gameHistory = await getState("gameHistory", []);
    return { success: true, games: gameHistory };
  } catch (e) {
    console.error("History fetch error:", e);
    return { success: false, error: e.message };
  }
}

function encodeVarint(n) {
  const bytes = [];
  if (n === 0n) return Buffer.from([0]);
  while (n > 0n) {
    let byte = Number(n & 127n);
    n = n >> 7n;
    if (n > 0n) byte |= 128;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

async function getLastBlockTime() {
  try {
    const hashRes = await fetch(`${mempoolBase}/blocks/tip/hash`);
    if (!hashRes.ok) throw new Error("Failed to get tip hash");
    const hash = await hashRes.text();
    const blockRes = await fetch(`${mempoolBase}/block/${hash}`);
    if (!blockRes.ok) throw new Error("Failed to get block");
    const block = await blockRes.json();
    return { success: true, timestamp: block.timestamp };
  } catch (e) {
    console.error("Get last block time error:", e);
    return { success: false, error: e.message };
  }
}

app.get("/init", async (req, res) => {
  try {
    console.log("Hit /init");
    const result = await init();
    res.json(result);
  } catch (e) {
    console.error("Init route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/poll", async (req, res) => {
  try {
    console.log("Hit /poll");
    const result = await pollActivity();
    res.json(result);
  } catch (e) {
    console.error("Poll route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/check", authAdmin, async (req, res) => {
  try {
    console.log("Hit /check");
    const result = await checkBlock();
    res.json(result);
  } catch (e) {
    console.error("Check route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/status", async (req, res) => {
  try {
    console.log("Hit /status");
    const contributors = await getState("contributors", {});
    const pendingContributors = await getState("pendingContributors", {});
    const potRaw = Object.values(contributors).reduce(
      (a, b) => a + BigInt(b),
      0n
    );
    const pendingPotRaw = Object.values(pendingContributors).reduce(
      (a, b) => a + BigInt(b.amount),
      0n
    );
    const pot = (potRaw / 10n ** BigInt(decimals || 0)).toString();
    const pendingPot = (
      pendingPotRaw / 10n ** BigInt(decimals || 0)
    ).toString();
    const contribStr = {};
    for (const k in contributors)
      contribStr[k] = (
        BigInt(contributors[k]) / 10n ** BigInt(decimals || 0)
      ).toString();
    const pendingStr = {};
    for (const k in pendingContributors)
      pendingStr[k] = {
        ...pendingContributors[k],
        amount: (
          BigInt(pendingContributors[k].amount) /
          10n ** BigInt(decimals || 0)
        ).toString(),
      };
    const lastWinner = await getState("lastWinner", null);
    const balanceResult = await getBalance();
    const hasOpenGame = balanceResult.success && BigInt(balanceResult.balance) > 0n;
    res.json({
      address,
      pot,
      pendingPot,
      contributors: contribStr,
      pendingContributors: pendingStr,
      lastWinner,
      hasOpenGame,
      balanceError: !balanceResult.success ? balanceResult.error : null,
    });
  } catch (e) {
    console.error("Status route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/balance", async (req, res) => {
  try {
    console.log("Hit /balance");
    const result = await getBalance();
    res.json(result);
  } catch (e) {
    console.error("Balance route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/history", async (req, res) => {
  try {
    console.log("Hit /history");
    const result = await getHistory();
    res.json(result);
  } catch (e) {
    console.error("History route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/reset", authAdmin, async (req, res) => {
  try {
    console.log("Hit /reset");
    await setState("contributors", {});
    await setState("pendingContributors", {});
    await setState("lastTxid", null);
    await setState("scannedHeight", 0);
    console.log("Contributors, pending, lastTxid, and scannedHeight reset manually");
    res.json({ success: true, message: "State reset" });
  } catch (e) {
    console.error("Reset route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/last-block-time", async (req, res) => {
  try {
    console.log("Hit /last-block-time");
    const result = await getLastBlockTime();
    res.json(result);
  } catch (e) {
    console.error("Last block time route error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.use((req, res, next) => {
  console.log(`404: ${req.url}`);
  res.status(404).json({ error: "Not Found" });
});

app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

app.listen(port, async () => {
  await connectRedis();
  await init();
  console.log(`Server running on port ${port}. Network: ${networkType}`);
});