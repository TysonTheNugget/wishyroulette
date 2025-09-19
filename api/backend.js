require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bip39 = require('bip39');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const { createClient } = require('@redis/client');
const rateLimit = require('express-rate-limit');

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);
const app = express();
const port = process.env.PORT || 10000;

app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const corsOptions = {
  origin: [
    'https://ruletfront.vercel.app',
    'https://wishyroulette.onrender.com',
    'http://localhost:10000',
    'http://localhost:3000',
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

if (!process.env.MNEMONIC) {
  console.error('Error: MNEMONIC environment variable is not set');
  process.exit(1);
}
if (!process.env.REDIS_URL) {
  console.error('Error: REDIS_URL environment variable is not set');
  process.exit(1);
}

const adminApiKey = process.env.API_KEY;
const networkType = process.env.NETWORK || 'testnet';
const network = networkType === 'testnet' ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
const mempoolBase = networkType === 'testnet' ? 'https://mempool.space/testnet/api' : 'https://mempool.space/api';
const ordiscanApiKey = process.env.ORDISCAN_API_KEY || '373a1e27-947f-4bd8-80c6-639a03014a16';
const baseUrl = networkType === 'testnet' ? 'https://api.unisat.io/v1' : 'https://api.ordiscan.com/v1';
const headers = { 'Authorization': `Bearer ${ordiscanApiKey}` };

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
const { address } = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });

const runeName = 'WISHYWASHYMACHINE';
let runeId = process.env.RUNE_ID || "865286:2249";
let decimals = Number(process.env.RUNE_DECIMALS ?? 0);

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: { tls: process.env.REDIS_URL.startsWith('rediss://') },
});
redisClient.on('error', err => console.error('Redis Client Error', err));

async function connectRedis() {
  if (!redisClient.isOpen) {
    try {
      await redisClient.connect();
      console.log('Redis connected successfully');
    } catch (e) {
      console.error('Redis connection failed:', e.message);
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
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
}

async function init() {
  console.log('Initializing rune info...');
  try {
    const res = await fetch(`${baseUrl}/rune/${runeName}`, { headers });
    const responseText = await res.text();
    if (!res.ok) {
      console.error(`Init failed: HTTP ${res.status}, Response: ${responseText}`);
      return { success: false, error: responseText };
    }
    const data = JSON.parse(responseText);
    if (data && typeof data.id === 'string' && data.id.includes(':')) {
      runeId = data.id;
    }
    if (Number.isInteger(data?.decimals)) {
      decimals = data.decimals;
    }
    console.log(`Rune ID: ${runeId}, Decimals: ${decimals}`);
    return { success: true, runeId, decimals };
  } catch (e) {
    console.error(`Init error: ${e.message}`);
    return { success: false, error: e.message };
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
          const rune = vout.runes.find(r => r.rune_name === runeName);
          if (rune) incomingAmount += BigInt(rune.amount || 0);
        }
      }
      if (incomingAmount > 0n) {
        sender = tx.vin[0]?.prevout?.scriptpubkey_address;
        if (sender && sender !== address) {
          const alias = Buffer.from(sender + txid).toString('base64').slice(0, 6).toUpperCase();
          pendingContributions.push({ sender, amount: incomingAmount.toString(), txid, status: 'pending', alias });
          console.log(`Pending contribution from ${sender}: ${incomingAmount} (txid: ${txid}, alias: ${alias})`);
        }
      }
    }
    return { success: true, pending: pendingContributions };
  } catch (e) {
    console.error('Mempool poll error:', e);
    return { success: false, error: e.message, pending: [] };
  }
}

async function pollActivity() {
  console.log(`Polling activity for address: ${address}`);
  try {
    let contributors = await getState('contributors', {});
    let lastTxid = await getState('lastTxid', null);
    let pendingContributors = await getState('pendingContributors', {});
    const pendingResult = await pollMempool();
    if (pendingResult.success) {
      for (const contrib of pendingResult.pending) {
        if (!pendingContributors[contrib.txid]) {
          pendingContributors[contrib.txid] = contrib;
        }
      }
      await setState('pendingContributors', pendingContributors);
    }
    const res = await fetch(`${baseUrl}/address/${address}/activity/runes?sort=newest`, { headers });
    if (!res.ok) {
      console.error(`Poll failed: HTTP ${res.status}`);
      return { success: false, error: await res.text() };
    }
    const response = await res.json();
    const data = response.data || [];
    let newContributions = 0;
    let newWithdrawals = 0;
    let totalPotAdjustment = 0n;
    for (const tx of data) {
      if (lastTxid && tx.txid === lastTxid) break;
      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      let sender = null;
      for (const out of tx.outputs) {
        if (out.address === address && out.rune === runeName) {
          incomingAmount += BigInt(out.rune_amount);
        }
      }
      const isFromOurAddress = tx.inputs.some(inp => inp.address === address && inp.rune === runeName);
      if (isFromOurAddress) {
        for (const out of tx.outputs) {
          if (out.rune === runeName && out.address !== address) {
            outgoingAmount += BigInt(out.rune_amount);
          }
        }
      }
      if (incomingAmount > 0n) {
        sender = tx.inputs.find(inp => inp.rune === runeName)?.address;
        if (sender && sender !== address) {
          contributors[sender] = (BigInt(contributors[sender] || 0) + incomingAmount).toString();
          newContributions++;
          console.log(`New contribution from ${sender}: ${incomingAmount.toString()}`);
        }
      }
      if (outgoingAmount > 0n) {
        totalPotAdjustment -= outgoingAmount;
        newWithdrawals++;
        console.log(`Detected outgoing transfer of ${outgoingAmount.toString()} WISHYWASHYMACHINE`);
      }
    }
    if (totalPotAdjustment < 0n) {
      let totalPot = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
      totalPot += totalPotAdjustment;
      if (totalPot <= 0n) {
        console.log('Outgoing transfer detected, checking if payout...');
        const lastPayout = await getState('lastPayout', null);
        if (!lastPayout || lastPayout.amount !== (-totalPotAdjustment).toString()) {
          console.log('Not a payout, preserving contributors');
        } else {
          contributors = {};
          console.log('Payout confirmed, reset contributors');
        }
      } else {
        const scale = totalPot / (totalPot - totalPotAdjustment);
        for (const sender in contributors) {
          contributors[sender] = (BigInt(Math.floor(Number(BigInt(contributors[sender])) * Number(scale)))).toString();
          if (BigInt(contributors[sender]) === 0n) delete contributors[sender];
        }
      }
    }
    if (data.length > 0) {
      lastTxid = data[0].txid;
      await setState('lastTxid', lastTxid);
      console.log(`Updated lastTxid to ${lastTxid}`);
    }
    let updatedPending = { ...pendingContributors };
    for (const txid in pendingContributors) {
      if (data.some(tx => tx.txid === txid)) {
        const pend = pendingContributors[txid];
        contributors[pend.sender] = (BigInt(contributors[pend.sender] || 0) + BigInt(pend.amount)).toString();
        delete updatedPending[txid];
      }
    }
    await setState('pendingContributors', updatedPending);
    const balanceResult = await getBalance();
    if (balanceResult.success) {
      const actualBalance = BigInt(balanceResult.balance);
      const currentPot = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
      if (actualBalance !== currentPot) {
        console.log(`Balance mismatch: contributors pot=${currentPot}, actual=${actualBalance}. Logging, not resetting...`);
        const pendingCheck = await fetch(`${mempoolBase}/address/${address}/txs/mempool`);
        if (actualBalance === 0n && pendingCheck.ok && (await pendingCheck.json()).length === 0) {
          console.log('No pending txs and balance 0, resetting contributors');
          contributors = {};
        }
        if (actualBalance > 0n && currentPot === 0n) {
          console.log('Pot empty but balance exists, syncing contributors to balance');
          contributors[address] = actualBalance.toString();
          await setState('contributors', contributors);
          lastTxid = null;
          await setState('lastTxid', null);
        }
      }
    }
    await setState('contributors', contributors);
    return { success: true, newContributions, newWithdrawals };
  } catch (e) {
    console.error('Poll activity error:', e);
    return { success: false, error: e.message };
  }
}

async function getCurrentHeight() {
  console.log('Fetching current block height...');
  try {
    const res = await fetch(`${mempoolBase}/blocks/tip/height`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const height = Number(await res.text());
    console.log(`Current height: ${height}`);
    return height;
  } catch (e) {
    console.error('Get height error:', e);
    return null;
  }
}

async function checkBlock() {
  console.log('Checking for new block...');
  try {
    let currentHeight = await getState('currentHeight', 0);
    let contributors = await getState('contributors', {});
    let lastWinner = await getState('lastWinner', null);
    let gameHistory = await getState('gameHistory', []);
    const height = await getCurrentHeight();
    if (height === null) return { success: false, error: 'Failed to get height' };
    if (height > currentHeight && currentHeight > 0) {
      console.log(`New block detected: ${height}. Triggering lottery for previous height ${height - 1}`);
      const pot = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
      if (pot > 0n) {
        console.log(`Pot value: ${pot.toString()}`);
        const prevHeight = height - 1;
        let hash;
        try {
          const blockRes = await fetch(`${mempoolBase}/block-height/${prevHeight}`);
          const responseText = await blockRes.text();
          if (!blockRes.ok) throw new Error(`mempool.space failed: HTTP ${blockRes.status}, ${responseText}`);
          hash = responseText.trim();
          console.log(`Using block hash ${hash} for randomness`);
        } catch (e) {
          console.error(`mempool.space error: ${e.message}`);
          return { success: false, error: `Block fetch error: ${e.message}` };
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
          console.log(`Winner selected: ${winner}`);
          const success = await payoutTo(winner);
          if (success) {
            console.log(`Payout of ${pot.toString()} WISHY to ${winner} completed`);
            gameHistory.unshift({ winner, amount: pot.toString(), timestamp: Date.now() });
            contributors = {};
            lastWinner = winner;
            await setState('contributors', contributors);
            await setState('lastWinner', lastWinner);
            await setState('lastPayout', { winner, amount: pot.toString(), timestamp: Date.now() });
            await setState('gameHistory', gameHistory);
            return { success: true, winner };
          } else {
            return { success: false, error: 'Payout failed' };
          }
        } else {
          console.log('No winner selected (edge case)');
          return { success: false, error: 'No winner' };
        }
      } else {
        console.log('Pot is empty, no lottery');
        return { success: true, message: 'Empty pot' };
      }
    } else {
      console.log(`No new block or initial height. Current: ${height}`);
    }
    currentHeight = height;
    await setState('currentHeight', currentHeight);
    return { success: true, message: 'No action' };
  } catch (e) {
    console.error('Check block error:', e);
    return { success: false, error: e.message };
  }
}

async function payoutTo(winnerAddress) {
  console.log(`Attempting payout to ${winnerAddress}`);
  if (!runeId || !runeId.includes(':')) {
    console.error(`Payout aborted: runeId invalid (${runeId})`);
    return false;
  }
  try {
    const utxoRes = await fetch(`${baseUrl}/address/${address}/utxos`, { headers });
    if (!utxoRes.ok) {
      const errorText = await utxoRes.text();
      console.error(`UTXO fetch failed: HTTP ${utxoRes.status}, ${errorText}`);
      return false;
    }
    const utxoResponse = await utxoRes.json();
    const utxos = utxoResponse.data || [];
    if (utxos.length === 0) {
      console.log('No UTXOs');
      return false;
    }
    let totalSats = 0n;
    let hasRune = false;
    let runeAmount = 0n;
    utxos.forEach(u => {
      totalSats += BigInt(u.value);
      if (u.runes) {
        u.runes.forEach(r => {
          if (r.name === runeName) {
            hasRune = true;
            runeAmount += BigInt(r.amount);
          }
        });
      }
    });
    console.log(`Total sats: ${totalSats}, Has rune: ${hasRune}, Rune amount: ${runeAmount.toString()}`);
    if (!hasRune) {
      console.log('No runes found in UTXOs');
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
      console.log('Insufficient sats for fee');
      return false;
    }
    const psbt = new bitcoin.Psbt({ network });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });
    for (const u of utxos) {
      if (!u.outpoint) {
        console.error(`Invalid UTXO: ${JSON.stringify(u)}`);
        continue;
      }
      const [h, idxStr] = u.outpoint.split(':');
      const script = u.script_pubkey ? Buffer.from(u.script_pubkey, 'hex') : p2wpkh.output;
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
    const [blockStr, txStr] = runeId.split(':');
    const deltaBlock = BigInt(blockStr);
    const deltaTx = BigInt(txStr);
    const amount = 0n;
    const payload = Buffer.concat([
      encodeVarint(0n),
      encodeVarint(deltaBlock),
      encodeVarint(deltaTx),
      encodeVarint(amount),
      encodeVarint(BigInt(outputIndex)),
    ]);
    const opReturnScript = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, bitcoin.opcodes.OP_13, payload]);
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
    const broadRes = await fetch(`${mempoolBase}/tx`, { method: 'POST', body: txHex });
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
      console.warn(`Ordiscan failed: HTTP ${res.status}, trying Hiro...`);
      res = await fetch(`https://api.hiro.so/ordinals/v1/addresses/${address}/runes-balances`);
    }
    if (!res.ok) {
      const errorText = await res.text();
      console.error(`Balance fetch failed: HTTP ${res.status}, ${errorText}`);
      return { success: false, error: errorText };
    }
    const response = await res.json();
    const data = response.data || response.results || [];
    let balance = 0n;
    for (const rune of data) {
      if (rune.rune_name === runeName || rune.name === runeName) {
        balance = BigInt(rune.amount || rune.balance);
        break;
      }
    }
    console.log(`Current rune balance: ${balance.toString()} WISHYWASHYMACHINE`);
    return { success: true, balance: balance.toString() };
  } catch (e) {
    console.error(`Balance fetch error: ${e.message}`);
    return { success: false, error: e.message };
  }
}

async function getHistory() {
  console.log('Fetching game history...');
  try {
    const gameHistory = await getState('gameHistory', []);
    return { success: true, games: gameHistory };
  } catch (e) {
    console.error('History fetch error:', e);
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
    if (!hashRes.ok) throw new Error('Failed to get tip hash');
    const hash = await hashRes.text();
    const blockRes = await fetch(`${mempoolBase}/block/${hash}`);
    if (!blockRes.ok) throw new Error('Failed to get block');
    const block = await blockRes.json();
    return { success: true, timestamp: block.timestamp };
  } catch (e) {
    console.error('Get last block time error:', e);
    return { success: false, error: e.message };
  }
}

app.get('/init', async (req, res) => {
  try {
    console.log('Hit /init');
    const result = await init();
    res.json(result);
  } catch (e) {
    console.error('Init route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/poll', async (req, res) => {
  try {
    console.log('Hit /poll');
    const result = await pollActivity();
    res.json(result);
  } catch (e) {
    console.error('Poll route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/check', authAdmin, async (req, res) => {
  try {
    console.log('Hit /check');
    const result = await checkBlock();
    res.json(result);
  } catch (e) {
    console.error('Check route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/status', async (req, res) => {
  try {
    console.log('Hit /status');
    const contributors = await getState('contributors', {});
    const pendingContributors = await getState('pendingContributors', {});
    const potRaw = Object.values(contributors).reduce((a, b) => a + BigInt(b), 0n);
    const pendingPotRaw = Object.values(pendingContributors).reduce((a, b) => a + BigInt(b.amount), 0n);
    const pot = (potRaw / (10n ** BigInt(decimals || 0))).toString();
    const pendingPot = (pendingPotRaw / (10n ** BigInt(decimals || 0))).toString();
    const contribStr = {};
    for (const k in contributors) contribStr[k] = (BigInt(contributors[k]) / (10n ** BigInt(decimals || 0))).toString();
    const pendingStr = {};
    for (const k in pendingContributors) pendingStr[k] = pendingContributors[k];
    const lastWinner = await getState('lastWinner', null);
    res.json({ address, pot, pendingPot, contributors: contribStr, pendingContributors: pendingStr, lastWinner });
  } catch (e) {
    console.error('Status route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/balance', async (req, res) => {
  try {
    console.log('Hit /balance');
    const result = await getBalance();
    res.json(result);
  } catch (e) {
    console.error('Balance route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/history', async (req, res) => {
  try {
    console.log('Hit /history');
    const result = await getHistory();
    res.json(result);
  } catch (e) {
    console.error('History route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/reset', authAdmin, async (req, res) => {
  try {
    console.log('Hit /reset');
    await setState('contributors', {});
    await setState('pendingContributors', {});
    await setState('lastTxid', null);
    console.log('Contributors, pending, and lastTxid reset manually');
    res.json({ success: true, message: 'State reset' });
  } catch (e) {
    console.error('Reset route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/last-block-time', async (req, res) => {
  try {
    console.log('Hit /last-block-time');
    const result = await getLastBlockTime();
    res.json(result);
  } catch (e) {
    console.error('Last block time route error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.use((req, res, next) => {
  console.log(`404: ${req.url}`);
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(port, async () => {
  await connectRedis();
  console.log(`Server running on port ${port}. Network: ${networkType}`);
});