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
const networkType = process.env.NETWORK || "mainnet";  // Changed to mainnet as per logs
const network =
  networkType === "testnet"
    ? bitcoin.networks.testnet
    : bitcoin.networks.bitcoin;
const mempoolBase =
  networkType === "testnet"
    ? "https://mempool.space/testnet/api"
    : "https://mempool.space/api";
const unisatBase = "https://open-api.unisat.io/v1/indexer/runes";
const unisatHeaders = {
  "User-Agent": "WishyWashyLottery/1.0",
  "Accept": "application/json"
};

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
let runeId = process.env.RUNE_ID || "865286:2249";  // Keep default, but log if not fetched
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
  await redisClient.set(key, JSON.stringify(value), { EX: 3600 });  // Expire in 1 hour
}

function authAdmin(req, res, next) {
  if (req.query.api_key !== adminApiKey) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  next();
}

async function fetchWithRetry(url, options = {}, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      console.warn(`Fetch failed (attempt ${i + 1}): ${res.status} ${res.statusText}`);
      if (i === maxRetries - 1) throw new Error(`HTTP ${res.status}`);
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    } catch (e) {
      if (i === maxRetries - 1) throw e;
      console.warn(`Fetch error (attempt ${i + 1}): ${e.message}`);
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    }
  }
}

async function init() {
  console.log("Initializing rune info and scanning history...");
  try {
    // Try to fetch rune info from Unisat
    let runeData = null;
    try {
      const res = await fetchWithRetry(`${unisatBase}/${runeName}/info`, { headers: unisatHeaders });
      const data = await res.json();
      runeData = data.data;
      if (runeData && runeData.id) {
        runeId = runeData.id;
        decimals = runeData.decimals || 0;
      }
    } catch (e) {
      console.warn("Rune info fetch failed, using defaults:", e.message);
    }
    console.log(`Rune ID: ${runeId}, Decimals: ${decimals}`);

    // Cache rune info
    await setState("runeInfo", { runeId, decimals });

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

    // For simplicity, limit scan to recent txs since full history is hard without proper API
    const recentTxs = await getRecentTransactions();
    let newContributions = 0;
    let newPayouts = 0;

    for (const tx of recentTxs) {
      if (lastTxid && tx.txid === lastTxid) break;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let recipient = null;

      // Parse tx for runes (simplified - in real, use full tx decode)
      if (tx.vout) {
        for (const vout of tx.vout) {
          if (vout.scriptpubkey_address === address && vout.runes && vout.runes.length > 0) {
            const rune = vout.runes.find(r => r.name === runeName || r.rune_name === runeName);
            if (rune) incomingAmount += BigInt(rune.amount || 0);
          } else if (vout.runes && vout.runes.length > 0 && vout.scriptpubkey_address !== address) {
            const rune = vout.runes.find(r => r.name === runeName || r.rune_name === runeName);
            if (rune) {
              outgoingAmount += BigInt(rune.amount || 0);
              recipient = vout.scriptpubkey_address;
            }
          }
        }
      }

      if (incomingAmount > 0n) {
        // For incoming, assume sender from vin (simplified)
        const sender = tx.vin && tx.vin.length > 0 ? tx.vin[0].prevout?.scriptpubkey_address : 'unknown';
        if (sender && sender !== address) {
          contributors[sender] = (BigInt(contributors[sender] || 0) + incomingAmount).toString();
          newContributions++;
          console.log(`Historical contribution from ${sender}: ${incomingAmount.toString()}`);
        }
      }

      if (outgoingAmount > 0n && recipient) {
        console.log(`Detected historical payout of ${outgoingAmount.toString()} to ${recipient}`);
        gameHistory.unshift({
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.status?.block_time * 1000 || Date.now(),
          txid: tx.txid,
        });
        contributors = {};  // Reset for new game
        await setState("lastWinner", recipient);
        await setState("lastPayout", {
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.status?.block_time * 1000 || Date.now(),
        });
        newPayouts++;
      }
    }

    if (recentTxs.length > 0) {
      lastTxid = recentTxs[0].txid;
      await setState("lastTxid", lastTxid);
    }

    await setState("contributors", contributors);
    await setState("gameHistory", gameHistory);
    console.log(`Historical scan completed: ${newContributions} contributions, ${newPayouts} payouts`);
  } catch (e) {
    console.error("Historical scan error:", e);
  }
}

async function getRecentTransactions() {
  console.log(`Fetching recent transactions for ${address}`);
  try {
    const res = await fetchWithRetry(`${mempoolBase}/address/${address}/txs?limit=50`);
    const txs = await res.json();
    // Filter for rune-related txs if possible
    return txs.filter(tx => tx.vout && tx.vout.some(v => v.runes && v.runes.length > 0));
  } catch (e) {
    console.error("Recent txs fetch error:", e);
    return [];
  }
}

async function pollMempool() {
  console.log(`Polling mempool for unconfirmed txs to ${address}`);
  try {
    const res = await fetchWithRetry(`${mempoolBase}/address/${address}/txs/mempool`);
    const txs = await res.json();
    let pendingContributions = [];
    for (const tx of txs) {
      const txid = tx.txid;
      let incomingAmount = 0n;
      let sender = null;
      for (const vout of tx.vout) {
        if (vout.scriptpubkey_address === address && vout.runes) {
          const rune = vout.runes.find((r) => r.name === runeName || r.rune_name === runeName);
          if (rune) incomingAmount += BigInt(rune.amount || 0);
        }
      }
      if (incomingAmount > 0n) {
        // Find sender from inputs
        for (const vin of tx.vin) {
          if (vin.prevout && vin.prevout.runes) {
            const rune = vin.prevout.runes.find(r => r.name === runeName || r.rune_name === runeName);
            if (rune && BigInt(rune.amount || 0) > 0n) {
              sender = vin.prevout.scriptpubkey_address;
              break;
            }
          }
        }
        if (sender && sender !== address) {
          const alias = Buffer.from(sender + txid).toString("base64").slice(0, 6).toUpperCase();
          pendingContributions.push({
            sender,
            amount: incomingAmount.toString(),
            txid,
            status: "pending",
            alias,
          });
          console.log(`Pending contribution from ${sender}: ${incomingAmount} (txid: ${txid})`);
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

    const recentTxs = await getRecentTransactions();
    let newContributions = 0;
    let newWithdrawals = 0;

    for (const tx of recentTxs) {
      if (lastTxid && tx.txid === lastTxid) break;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let recipient = null;

      if (tx.vout) {
        for (const vout of tx.vout) {
          if (vout.scriptpubkey_address === address && vout.runes) {
            const rune = vout.runes.find(r => r.name === runeName || r.rune_name === runeName);
            if (rune) incomingAmount += BigInt(rune.amount || 0);
          } else if (vout.runes && vout.scriptpubkey_address !== address) {
            const rune = vout.runes.find(r => r.name === runeName || r.rune_name === runeName);
            if (rune) {
              outgoingAmount += BigInt(rune.amount || 0);
              recipient = vout.scriptpubkey_address;
            }
          }
        }
      }

      if (incomingAmount > 0n) {
        const sender = tx.vin && tx.vin.length > 0 ? tx.vin[0].prevout?.scriptpubkey_address : 'unknown';
        if (sender && sender !== address) {
          contributors[sender] = (BigInt(contributors[sender] || 0) + incomingAmount).toString();
          newContributions++;
          console.log(`New contribution from ${sender}: ${incomingAmount.toString()}`);
        }
      }

      if (outgoingAmount > 0n && recipient) {
        console.log(`Detected outgoing transfer of ${outgoingAmount.toString()} to ${recipient}`);
        gameHistory.unshift({
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.status?.block_time * 1000 || Date.now(),
          txid: tx.txid,
        });
        contributors = {};
        await setState("lastWinner", recipient);
        await setState("lastPayout", {
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.status?.block_time * 1000 || Date.now(),
        });
        newWithdrawals++;
      }
    }

    if (recentTxs.length > 0) {
      lastTxid = recentTxs[0].txid;
      await setState("lastTxid", lastTxid);
    }

    let updatedPending = { ...pendingContributors };
    for (const txid in pendingContributors) {
      if (recentTxs.some((tx) => tx.txid === txid)) {
        const pend = pendingContributors[txid];
        contributors[pend.sender] = (BigInt(contributors[pend.sender] || 0) + BigInt(pend.amount)).toString();
        delete updatedPending[txid];
      }
    }
    await setState("pendingContributors", updatedPending);
    await setState("contributors", contributors);
    await setState("gameHistory", gameHistory);

    const balanceResult = await getBalance();
    if (balanceResult.success && BigInt(balanceResult.balance) > 0n) {
      console.log(`Balance exists (${balanceResult.balance}), open game detected`);
    } else {
      console.log(`No balance or fetch failed: ${balanceResult.error || '0'}`);
    }

    return { success: true, newContributions, newWithdrawals };
  } catch (e) {
    console.error("Poll activity error:", e);
    return { success: false, error: e.message };
  }
}

async function getCurrentHeight() {
  console.log("Fetching current block height...");
  try {
    const res = await fetchWithRetry(`${mempoolBase}/blocks/tip/height`);
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
    const height = await getCurrentHeight();
    if (height === null) return { success: false, error: "Failed to get height" };

    if (height > currentHeight) {
      console.log(`New block detected: ${height}`);
      const pot = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
      if (pot > 0n) {
        const prevHeight = height - 1;
        let hash;
        try {
          const blockRes = await fetchWithRetry(`${mempoolBase}/block-height/${prevHeight}`);
          hash = await blockRes.text();
          hash = hash.trim();
        } catch (e) {
          console.error(`Block hash fetch error: ${e.message}`);
          return { success: false, error: "Block hash fetch failed" };
        }
        const rand = BigInt(`0x${hash}`) % pot;
        const entries = Object.entries(contributors).sort((a, b) => a[0].localeCompare(b[0]));
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
          console.log(`Winner selected: ${winner.slice(0, 8)}...`);
          const success = await payoutTo(winner);
          if (success) {
            console.log(`Payout to ${winner.slice(0, 8)}... completed`);
            const gameHistory = await getState("gameHistory", []);
            gameHistory.unshift({
              winner,
              amount: pot.toString(),
              timestamp: Date.now(),
              txid: null,
            });
            await setState("gameHistory", gameHistory);
            await setState("contributors", {});
            await setState("lastWinner", winner);
            return { success: true, winner };
          } else {
            return { success: false, error: "Payout failed" };
          }
        }
      } else {
        console.log("Pot is empty, no lottery");
      }
    }
    await setState("currentHeight", height);
    return { success: true, message: "No action" };
  } catch (e) {
    console.error("Check block error:", e);
    return { success: false, error: e.message };
  }
}

async function payoutTo(winnerAddress) {
  console.log(`Attempting payout to ${winnerAddress.slice(0, 8)}...`);
  if (!runeId || !runeId.includes(":")) {
    console.error(`Payout aborted: runeId invalid (${runeId})`);
    return false;
  }
  try {
    // Fetch UTXOs from mempool
    const res = await fetchWithRetry(`${mempoolBase}/address/${address}/utxos`);
    const utxos = await res.json();
    if (utxos.length === 0) {
      console.log("No UTXOs available");
      return false;
    }
    let totalSats = 0n;
    let hasRune = false;
    let runeAmount = 0n;
    utxos.forEach((u) => {
      totalSats += BigInt(u.value);
      if (u.runes && u.runes.length > 0) {
        const rune = u.runes.find(r => r.name === runeName || r.rune_name === runeName);
        if (rune) {
          hasRune = true;
          runeAmount += BigInt(rune.amount || 0);
        }
      }
    });
    if (!hasRune) {
      console.log("No WISHYWASHYMACHINE runes found in UTXOs");
      return false;
    }
    console.log(`Rune amount to payout: ${runeAmount.toString()}`);

    // Fee estimation
    const feeRes = await fetchWithRetry(`${mempoolBase}/v1/fees/recommended`);
    const fees = await feeRes.json();
    const feeRate = fees.economyFee || 5;
    const txSize = 112 + utxos.length * 68 + 34;  // Approximate size
    let fee = BigInt(feeRate * txSize);
    const dust = 546n;
    let change = totalSats - dust - fee;
    if (change < 0n) {
      console.log("Insufficient sats for fee");
      return false;
    }

    // Build PSBT for rune transfer (simplified - full implementation needs rune etching logic)
    const psbt = new bitcoin.Psbt({ network });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });

    // Add inputs
    for (const u of utxos) {
      const [txid, vout] = u.txid ? [u.txid, u.vout] : u.outpoint.split(':');
      psbt.addInput({
        hash: txid,
        index: parseInt(vout),
        witnessUtxo: { value: parseInt(u.value), script: p2wpkh.output },
      });
    }

    // Add outputs
    psbt.addOutput({ address: winnerAddress, value: parseInt(dust) });
    if (change >= dust) {
      psbt.addOutput({ address, value: parseInt(change) });
    }

    // Add rune transfer OP_RETURN (simplified encoding)
    const [blockStr, txStr] = runeId.split(":");
    const edict = Buffer.concat([
      encodeVarint(0n),  // etching
      encodeVarint(BigInt(blockStr)),
      encodeVarint(BigInt(txStr)),
      encodeVarint(runeAmount),
      encodeVarint(0n),  // output index for transfer
    ]);
    const opReturn = bitcoin.script.fromASM(`OP_RETURN ${edict.toString('hex')}`);
    psbt.addOutput({ script: opReturn, value: 0 });

    // Sign
    const signer = { publicKey: child.publicKey, sign: (hash) => child.signSchnorr(hash) };
    for (let i = 0; i < utxos.length; i++) {
      psbt.signInput(i, signer);
    }
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction().toHex();

    // Broadcast
    const broadRes = await fetch(`${mempoolBase}/tx`, { method: "POST", body: tx });
    if (broadRes.ok) {
      const txid = await broadRes.text();
      console.log(`Payout broadcast: ${txid}`);
      return true;
    } else {
      const error = await broadRes.text();
      console.error(`Broadcast failed: ${error}`);
      return false;
    }
  } catch (e) {
    console.error(`Payout error: ${e.message}`);
    return false;
  }
}

async function getBalance() {
  console.log(`Fetching rune balance for ${address}`);
  try {
    // Try Unisat first
    const res = await fetchWithRetry(`${unisatBase}/address/${address}/runes/balance`);
    const data = await res.json();
    let balance = 0n;
    if (data.data && data.data.runes) {
      const rune = data.data.runes.find(r => r.name === runeName);
      if (rune) balance = BigInt(rune.balance || 0);
    }
    if (balance > 0n) {
      console.log(`Unisat balance: ${balance.toString()}`);
      return { success: true, balance: balance.toString() };
    }
  } catch (e) {
    console.warn("Unisat balance fetch failed:", e.message);
  }

  // Fallback to mempool UTXO scan
  try {
    const res = await fetchWithRetry(`${mempoolBase}/address/${address}/utxos`);
    const utxos = await res.json();
    let balance = 0n;
    for (const u of utxos) {
      if (u.runes) {
        const rune = u.runes.find(r => r.name === runeName || r.rune_name === runeName);
        if (rune) balance += BigInt(rune.amount || 0);
      }
    }
    console.log(`Mempool balance: ${balance.toString()}`);
    return { success: true, balance: balance.toString() };
  } catch (e) {
    console.error("Mempool balance fetch failed:", e.message);
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
    n >>= 7n;
    if (n > 0n) byte |= 128;
    bytes.push(byte);
  }
  return Buffer.from(bytes.reverse());
}

async function getLastBlockTime() {
  try {
    const hashRes = await fetchWithRetry(`${mempoolBase}/blocks/tip/hash`);
    const hash = (await hashRes.text()).trim();
    const blockRes = await fetchWithRetry(`${mempoolBase}/block/${hash}`);
    const block = await blockRes.json();
    return { success: true, timestamp: block.timestamp };
  } catch (e) {
    console.error("Get last block time error:", e);
    return { success: false, error: e.message };
  }
}

// Routes
app.get("/init", async (req, res) => {
  try {
    const result = await init();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/poll", async (req, res) => {
  try {
    const result = await pollActivity();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/check", authAdmin, async (req, res) => {
  try {
    const result = await checkBlock();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/status", async (req, res) => {
  try {
    const contributors = await getState("contributors", {});
    const pendingContributors = await getState("pendingContributors", {});
    const { runeId: cachedRuneId, decimals: cachedDecimals } = await getState("runeInfo", { runeId, decimals });
    const potRaw = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
    const pendingPotRaw = Object.values(pendingContributors).reduce((a, b) => a + BigInt(b.amount), 0n);
    const pot = (potRaw / 10n ** BigInt(cachedDecimals)).toString();
    const pendingPot = (pendingPotRaw / 10n ** BigInt(cachedDecimals)).toString();
    const contribStr = {};
    for (const k in contributors) {
      contribStr[k] = (BigInt(contributors[k]) / 10n ** BigInt(cachedDecimals)).toString();
    }
    const pendingStr = {};
    for (const k in pendingContributors) {
      pendingStr[k] = {
        ...pendingContributors[k],
        amount: (BigInt(pendingContributors[k].amount) / 10n ** BigInt(cachedDecimals)).toString(),
      };
    }
    const lastWinner = await getState("lastWinner", null);
    const balanceResult = await getBalance();
    const hasOpenGame = balanceResult.success && BigInt(balanceResult.balance) > 0n;
    res.json({
      success: true,
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
    const result = await getBalance();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/history", async (req, res) => {
  try {
    const result = await getHistory();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/reset", authAdmin, async (req, res) => {
  try {
    await setState("contributors", {});
    await setState("pendingContributors", {});
    await setState("lastTxid", null);
    await setState("scannedHeight", 0);
    await setState("gameHistory", []);
    await setState("lastWinner", null);
    console.log("State reset");
    res.json({ success: true, message: "State reset" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/last-block-time", async (req, res) => {
  try {
    const result = await getLastBlockTime();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use((req, res) => {
  console.log(`${req.method} ${req.url} - 404`);
  res.status(404).json({ error: "Not Found" });
});

app.listen(port, async () => {
  await connectRedis();
  await init();
  console.log(`Server running on port ${port}. Network: ${networkType}. Address: ${address}`);
});