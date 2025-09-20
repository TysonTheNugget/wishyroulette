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
const networkType = "mainnet"; // Fixed to mainnet only
const network = bitcoin.networks.bitcoin;
const mempoolBase = "https://mempool.space/api";
const unisatBaseUrl = "https://open-api.unisat.io/v1/indexer";
const ordiscanBaseUrl = "https://api.ordiscan.com/v1";
const unisatApiKey = process.env.UNISAT_API_KEY || ""; // Get from unisat.io/plans
const ordiscanApiKey = process.env.ORDISCAN_API_KEY || "373a1e27-947f-4bd8-80c6-639a03014a16";
const unisatHeaders = unisatApiKey ? { Authorization: `Bearer ${unisatApiKey}` } : {};
const ordiscanHeaders = { Authorization: `Bearer ${ordiscanApiKey}` };

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

const runeName = process.env.RUNE_NAME || "WISHYWASHYMACHINE";
let runeId = process.env.RUNE_ID || "865286:2249"; // Update if known
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

async function fetchWithRetry(url, options = {}, maxAttempts = 3) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      const text = await res.text();
      console.error(`Fetch attempt ${attempt} failed for ${url}: HTTP ${res.status} - ${text}`);
      if (attempt === maxAttempts) throw new Error(`Failed after ${maxAttempts} attempts: ${text}`);
      await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
    } catch (e) {
      console.error(`Fetch error on attempt ${attempt} for ${url}: ${e.message}`);
      if (attempt === maxAttempts) throw e;
      await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
    }
  }
}

async function init() {
  console.log("Initializing rune info and scanning history on mainnet...");
  try {
    // Load cached rune info
    const cachedRune = await getState("runeInfo", null);
    if (cachedRune) {
      runeId = cachedRune.runeId;
      decimals = cachedRune.decimals;
      console.log(`Using cached rune info: ID ${runeId}, Decimals ${decimals}`);
    }

    // Fetch rune info from UniSat
    let runeData = null;
    try {
      const res = await fetchWithRetry(`${unisatBaseUrl}/runes/${runeName}`);
      const data = await res.json();
      if (data.code === 0 && data.data) {
        runeData = data.data;
        runeId = runeData.id || runeId;
        decimals = runeData.divisibility || decimals;
        console.log(`Fetched rune info: ID ${runeId}, Decimals ${decimals}`);
      } else {
        console.warn(`UniSat rune fetch failed, trying Ordiscan...`);
        const ordRes = await fetchWithRetry(`${ordiscanBaseUrl}/rune/${runeName}`, { headers: ordiscanHeaders });
        const ordData = await ordRes.json();
        if (ordData.code === 0 && ordData.data) {
          runeData = ordData.data;
          runeId = runeData.id;
          decimals = runeData.divisibility || 0;
          console.log(`Ordiscan rune info: ID ${runeId}, Decimals ${decimals}`);
        }
      }
    } catch (e) {
      console.error(`Rune fetch error: ${e.message}. Using defaults/cached.`);
    }

    if (runeData) {
      await setState("runeInfo", { runeId, decimals });
    }

    // Perform historical scan
    await scanHistoricalTransactions();

    return { success: true, runeId, decimals };
  } catch (e) {
    console.error(`Init error: ${e.message}`);
    return { success: false, error: e.message };
  }
}

async function scanHistoricalTransactions() {
  console.log(`Scanning historical transactions for address: ${address} on mainnet`);
  try {
    let contributors = await getState("contributors", {});
    let gameHistory = await getState("gameHistory", []);
    let lastTxid = await getState("lastTxid", null);

    // Fetch from Ordiscan (reliable for runes activity)
    let data = [];
    try {
      const res = await fetchWithRetry(`${ordiscanBaseUrl}/address/${address}/activity/runes?sort=oldest`, { headers: ordiscanHeaders });
      const response = await res.json();
      data = response.data || [];
      console.log(`Fetched ${data.length} historical txs from Ordiscan`);
    } catch (e) {
      console.error(`Ordiscan history fetch failed: ${e.message}, trying UniSat...`);
      const uniRes = await fetchWithRetry(`${unisatBaseUrl}/address/${address}/runes/history`);
      const uniData = await uniRes.json();
      data = uniData.data || [];
    }

    for (const tx of data) {
      if (lastTxid && tx.txid === lastTxid) continue;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let recipient = null;

      // Process outputs
      for (const out of (tx.outputs || [])) {
        if (out.address === address && out.rune === runeName) {
          incomingAmount += BigInt(out.amount || 0);
        }
        if (out.rune === runeName && out.address !== address) {
          outgoingAmount += BigInt(out.amount || 0);
          recipient = out.address;
        }
      }

      // Find senders from inputs
      const senders = (tx.inputs || [])
        .filter((inp) => inp.address && inp.address !== address && inp.rune === runeName)
        .map((inp) => inp.address);

      if (incomingAmount > 0n && senders.length > 0) {
        for (const s of senders) {
          contributors[s] = (BigInt(contributors[s] || 0) + incomingAmount).toString();
          console.log(`Historical contribution from ${s.slice(0, 8)}...: ${incomingAmount.toString()}`);
        }
      }

      if (outgoingAmount > 0n && recipient) {
        console.log(`Detected historical payout of ${outgoingAmount} to ${recipient.slice(0, 8)}...`);
        gameHistory.unshift({
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.timestamp || Date.now(),
          txid: tx.txid,
        });
        contributors = {}; // Reset for new game
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
    }

    await setState("contributors", contributors);
    await setState("gameHistory", gameHistory);
    console.log("Historical scan completed");
  } catch (e) {
    console.error("Historical scan error:", e);
  }
}

async function pollMempool() {
  console.log(`Polling mempool for unconfirmed txs to ${address}`);
  try {
    const res = await fetch(`${mempoolBase}/address/${address}/txs/mempool`);
    if (!res.ok) return { success: false, error: await res.text(), pending: [] };
    const txs = await res.json();
    let pendingContributions = [];
    for (const tx of txs) {
      const txid = tx.txid;
      let incomingAmount = 0n;
      let sender = null;
      for (const vout of (tx.vout || [])) {
        if (vout.scriptpubkey_address === address && vout.runes) {
          const rune = vout.runes.find((r) => r.name === runeName);
          if (rune) incomingAmount += BigInt(rune.amount || 0);
        }
      }
      if (incomingAmount > 0n) {
        for (const vin of (tx.vin || [])) {
          if (vin.prevout && vin.prevout.runes) {
            const rune = vin.prevout.runes.find((r) => r.name === runeName);
            if (rune && BigInt(rune.amount || 0) > 0n) {
              sender = vin.prevout.scriptpubkey_address;
              break;
            }
          }
        }
        if (sender && sender !== address) {
          const alias = Buffer.from(sender + txid).toString("base64").slice(0, 6).toUpperCase();
          pendingContributions.push({ sender, amount: incomingAmount.toString(), txid, status: "pending", alias });
          console.log(`Pending from ${sender.slice(0, 8)}...: ${incomingAmount.toString()}`);
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
        if (!pendingContributors[contrib.txid]) pendingContributors[contrib.txid] = contrib;
      }
      await setState("pendingContributors", pendingContributors);
    }

    // Fetch recent activity from Ordiscan
    const res = await fetchWithRetry(`${ordiscanBaseUrl}/address/${address}/activity/runes?sort=newest`, { headers: ordiscanHeaders });
    const response = await res.json();
    const data = response.data || [];

    let newContributions = 0;
    let newWithdrawals = 0;
    for (const tx of data) {
      if (lastTxid && tx.txid === lastTxid) break;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let recipient = null;

      for (const out of (tx.outputs || [])) {
        if (out.address === address && out.rune === runeName) incomingAmount += BigInt(out.amount || 0);
        if (out.rune === runeName && out.address !== address) {
          outgoingAmount += BigInt(out.amount || 0);
          recipient = out.address;
        }
      }

      const senders = (tx.inputs || [])
        .filter((inp) => inp.address && inp.address !== address && inp.rune === runeName)
        .map((inp) => inp.address);

      if (incomingAmount > 0n && senders.length > 0) {
        for (const s of senders) {
          contributors[s] = (BigInt(contributors[s] || 0) + incomingAmount).toString();
          newContributions++;
          console.log(`New contribution from ${s.slice(0, 8)}...: ${incomingAmount.toString()}`);
        }
      }

      if (outgoingAmount > 0n && recipient) {
        console.log(`Outgoing transfer of ${outgoingAmount} to ${recipient.slice(0, 8)}...`);
        gameHistory.unshift({
          winner: recipient,
          amount: outgoingAmount.toString(),
          timestamp: tx.timestamp || Date.now(),
          txid: tx.txid,
        });
        contributors = {};
        await setState("lastWinner", recipient);
        await setState("lastPayout", { winner: recipient, amount: outgoingAmount.toString(), timestamp: tx.timestamp || Date.now() });
        newWithdrawals++;
      }
    }

    if (data.length > 0) {
      lastTxid = data[0].txid;
      await setState("lastTxid", lastTxid);
    }

    let updatedPending = { ...pendingContributors };
    for (const txid in pendingContributors) {
      if (data.some((tx) => tx.txid === txid)) {
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
      console.log(`Open game detected: balance ${balanceResult.balance}`);
    }

    return { success: true, newContributions, newWithdrawals };
  } catch (e) {
    console.error("Poll activity error:", e);
    return { success: false, error: e.message };
  }
}

async function getCurrentHeight() {
  try {
    const res = await fetch(`${mempoolBase}/blocks/tip/height`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Number(await res.text());
  } catch (e) {
    console.error("Get height error:", e);
    return null;
  }
}

async function checkBlock() {
  console.log("Checking for new block on mainnet...");
  try {
    let currentHeight = await getState("currentHeight", 0);
    let contributors = await getState("contributors", {});
    const height = await getCurrentHeight();
    if (height === null || height <= currentHeight) {
      await setState("currentHeight", height || currentHeight);
      return { success: true, message: "No new block" };
    }

    console.log(`New block ${height}, checking lottery...`);
    const pot = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
    if (pot <= 0n) {
      await setState("currentHeight", height);
      return { success: true, message: "Empty pot" };
    }

    const prevHeight = height - 1;
    const blockRes = await fetch(`${mempoolBase}/block-height/${prevHeight}`);
    if (!blockRes.ok) throw new Error(`Block fetch failed: ${await blockRes.text()}`);
    const hash = (await blockRes.text()).trim();
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
      console.log(`Winner: ${winner.slice(0, 8)}...`);
      const success = await payoutTo(winner);
      if (success) {
        const gameHistory = await getState("gameHistory", []);
        gameHistory.unshift({ winner, amount: pot.toString(), timestamp: Date.now(), txid: null });
        await setState("gameHistory", gameHistory);
        await setState("contributors", {});
        await setState("lastWinner", winner);
        await setState("currentHeight", height);
        return { success: true, winner };
      }
    }

    await setState("currentHeight", height);
    return { success: false, error: "No winner or payout failed" };
  } catch (e) {
    console.error("Check block error:", e);
    return { success: false, error: e.message };
  }
}

async function payoutTo(winnerAddress) {
  console.log(`Payout to ${winnerAddress.slice(0, 8)}... on mainnet`);
  try {
    const utxoRes = await fetchWithRetry(`${unisatBaseUrl}/address/${address}/utxo-data`, { headers: unisatHeaders });
    const utxoData = await utxoRes.json();
    const utxos = utxoData.data || [];
    if (utxos.length === 0) return false;

    let totalSats = 0n;
    let hasRune = false;
    let runeAmount = 0n;
    for (const u of utxos) {
      totalSats += BigInt(u.value);
      if (u.runes) {
        const rune = u.runes.find(r => r.name === runeName);
        if (rune) {
          hasRune = true;
          runeAmount += BigInt(rune.amount);
        }
      }
    }
    if (!hasRune || runeAmount === 0n) return false;

    const feeRes = await fetch(`${mempoolBase}/v1/fees/recommended`);
    const fees = await feeRes.json();
    const feeRate = fees.economyFee;
    const txSize = 10 + utxos.length * 68 + 34 * 3 + 20;
    let fee = BigInt(feeRate * txSize);
    const dust = 546n;
    let change = totalSats - dust - fee;
    if (change < 0n) return false;

    const psbt = new bitcoin.Psbt({ network });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });

    for (const u of utxos) {
      const [h, idxStr] = u.tx_hash + ":" + u.index;
      const script = Buffer.from(u.scriptpubkey, "hex");
      psbt.addInput({
        hash: h.split(":")[0],
        index: Number(idxStr.split(":")[1]),
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
    const payload = Buffer.concat([
      encodeVarint(0n),
      encodeVarint(deltaBlock),
      encodeVarint(deltaTx),
      encodeVarint(runeAmount),
      encodeVarint(BigInt(outputIndex)),
    ]);
    const opReturnScript = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, bitcoin.opcodes.OP_13, payload]);
    psbt.addOutput({ script: opReturnScript, value: 0 });

    const signer = {
      publicKey: Buffer.from(child.publicKey),
      sign: (hash) => Buffer.from(child.sign(hash)),
    };
    for (let i = 0; i < utxos.length; i++) psbt.signInput(i, signer);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    const broadRes = await fetch(`${mempoolBase}/tx`, { method: "POST", body: txHex });
    if (broadRes.ok) {
      const txid = await broadRes.text();
      console.log(`Payout broadcast: TXID ${txid}`);
      return true;
    } else {
      console.error(`Broadcast failed: ${await broadRes.text()}`);
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
    // UniSat specific rune balance
    const res = await fetchWithRetry(`${unisatBaseUrl}/address/${address}/runes/${runeId}/balance`, { headers: unisatHeaders });
    if (res.ok) {
      const data = await res.json();
      if (data.code === 0 && data.data) {
        const balance = BigInt(data.data.balance || 0);
        console.log(`UniSat balance: ${balance.toString()}`);
        return { success: true, balance: balance.toString() };
      }
    }

    // Fallback to Ordiscan
    console.warn("UniSat balance failed, trying Ordiscan...");
    const ordRes = await fetchWithRetry(`${ordiscanBaseUrl}/address/${address}/runes`, { headers: ordiscanHeaders });
    const ordData = await ordRes.json();
    if (ordData.code === 0) {
      for (const rune of (ordData.data || [])) {
        if (rune.name === runeName) {
          const balance = BigInt(rune.balance || 0);
          console.log(`Ordiscan balance: ${balance.toString()}`);
          return { success: true, balance: balance.toString() };
        }
      }
    }

    return { success: false, error: "All balance APIs failed" };
  } catch (e) {
    console.error(`Balance error: ${e.message}`);
    return { success: false, error: e.message };
  }
}

async function getHistory() {
  try {
    const gameHistory = await getState("gameHistory", []);
    return { success: true, games: gameHistory };
  } catch (e) {
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
  return Buffer.from(bytes);
}

async function getLastBlockTime() {
  try {
    const hashRes = await fetch(`${mempoolBase}/blocks/tip/hash`);
    const hash = await hashRes.text();
    const blockRes = await fetch(`${mempoolBase}/block/${hash}`);
    const block = await blockRes.json();
    return { success: true, timestamp: block.timestamp };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Routes
app.get("/init", async (req, res) => {
  const result = await init();
  res.json(result);
});

app.get("/poll", async (req, res) => {
  const result = await pollActivity();
  res.json(result);
});

app.get("/check", authAdmin, async (req, res) => {
  const result = await checkBlock();
  res.json(result);
});

app.get("/status", async (req, res) => {
  try {
    const contributors = await getState("contributors", {});
    const pendingContributors = await getState("pendingContributors", {});
    const potRaw = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
    const pendingPotRaw = Object.values(pendingContributors).reduce((a, b) => a + BigInt(b.amount), 0n);
    const pot = (potRaw / (10n ** BigInt(decimals))).toString();
    const pendingPot = (pendingPotRaw / (10n ** BigInt(decimals))).toString();
    const contribStr = {};
    for (const k in contributors) contribStr[k] = (BigInt(contributors[k]) / (10n ** BigInt(decimals))).toString();
    const pendingStr = {};
    for (const k in pendingContributors) {
      pendingStr[k] = { ...pendingContributors[k], amount: (BigInt(pendingContributors[k].amount) / (10n ** BigInt(decimals))).toString() };
    }
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
      balanceError: balanceResult.success ? null : balanceResult.error,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/balance", async (req, res) => await res.json(await getBalance()));

app.get("/history", async (req, res) => await res.json(await getHistory()));

app.get("/reset", authAdmin, async (req, res) => {
  await setState("contributors", {});
  await setState("pendingContributors", {});
  await setState("lastTxid", null);
  await setState("scannedHeight", 0);
  res.json({ success: true, message: "Reset" });
});

app.get("/last-block-time", async (req, res) => await res.json(await getLastBlockTime()));

app.listen(port, async () => {
  await connectRedis();
  await init();
  console.log(`Mainnet server on port ${port}`);
});