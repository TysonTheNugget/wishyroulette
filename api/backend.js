require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const bip39 = require('bip39');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
bitcoin.initEccLib(ecc); // Initialize ECC library
const bip32 = BIP32Factory(ecc);
const app = express();
const port = process.env.PORT || 3000; // Use Render's PORT or default to 3000
app.use(express.static('public')); // Serve index.html from public folder
const mnemonic = process.env.MNEMONIC;
const seed = bip39.mnemonicToSeedSync(mnemonic);
const root = bip32.fromSeed(seed, bitcoin.networks.bitcoin); // For testnet, use bitcoin.networks.testnet
const child = root.derivePath("m/84'/0'/0'/0/0");
const { address } = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network: bitcoin.networks.bitcoin }); // For testnet, use bitcoin.networks.testnet
const apiKey = '373a1e27-947f-4bd8-80c6-639a03014a16';
const baseUrl = 'https://api.ordiscan.com/v1';
const headers = { 'Authorization': `Bearer ${apiKey}` };
const runeName = 'WISHYWASHYMACHINE';
let runeId = process.env.RUNE_ID || "865286:2249"; // WISHYWASHYMACHINE
let decimals = Number(process.env.RUNE_DECIMALS ?? 0);
let contributors = {}; // { address: BigInt amount }
let lastTxid = null;
let currentHeight = 0;
let lastWinner = null;
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
async function pollActivity() {
  console.log(`Polling activity for address: ${address}`);
  try {
    const res = await fetch(`${baseUrl}/address/${address}/activity/runes?sort=newest`, { headers });
    if (!res.ok) {
      console.error(`Poll failed: HTTP ${res.status}`);
      return { success: false, error: await res.text() };
    }
    const response = await res.json();
    const data = response.data || [];
    let newContributions = 0;
    for (const tx of data) {
      if (lastTxid && tx.txid === lastTxid) break;
      let incomingAmount = 0n;
      let sender = null;
      for (const out of tx.outputs) {
        if (out.address === address && out.rune === runeName) {
          incomingAmount += BigInt(out.rune_amount);
        }
      }
      if (incomingAmount > 0n) {
        const inputAddresses = new Set(tx.inputs.map(i => i.address));
        if (inputAddresses.size === 1) {
          sender = [...inputAddresses][0];
        } else {
          for (const inp of tx.inputs) {
            if (inp.rune === runeName) {
              sender = inp.address;
              break;
            }
          }
        }
        if (sender && sender !== address) {
          contributors[sender] = (contributors[sender] || 0n) + incomingAmount;
          newContributions++;
          console.log(`New contribution from ${sender}: ${incomingAmount.toString()}`);
        }
      }
    }
    if (data.length > 0) {
      lastTxid = data[0].txid;
      console.log(`Updated lastTxid to ${lastTxid}`);
    }
    const totalPot = Object.values(contributors).reduce((a, b) => a + b, 0n);
    console.log(`Total pot: ${totalPot.toString()} WISHYWASHYMACHINE`);
    return { success: true, newContributions };
  } catch (e) {
    console.error('Poll activity error:', e);
    return { success: false, error: e.message };
  }
}
async function getCurrentHeight() {
  console.log('Fetching current block height...');
  try {
    const res = await fetch('https://mempool.space/api/blocks/tip/height'); // For testnet, use https://mempool.space/testnet/api/...
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
  const height = await getCurrentHeight();
  if (height === null) return { success: false, error: 'Failed to get height' };
  if (height > currentHeight && currentHeight > 0) {
    console.log(`New block detected: ${height}. Triggering lottery for previous height ${height - 1}`);
    const pot = Object.values(contributors).reduce((a, b) => a + b, 0n);
    if (pot > 0n) {
      console.log(`Pot value: ${pot.toString()}`);
      const prevHeight = height - 1;
      let hash;
      try {
        const blockRes = await fetch(`https://mempool.space/api/block-height/${prevHeight}`);
        const responseText = await blockRes.text();
        if (!blockRes.ok) throw new Error(`mempool.space failed: HTTP ${blockRes.status}, ${responseText}`);
        hash = responseText.trim();
        console.log(`Using block hash ${hash} for randomness (from mempool.space)`);
      } catch (e) {
        console.error(`mempool.space error: ${e.message}`);
        return { success: false, error: `Block fetch error: ${e.message}` };
      }
      const rand = BigInt(`0x${hash}`) % pot;
      const entries = Object.entries(contributors).sort((a, b) => a[0].localeCompare(b[0]));
      let cum = 0n;
      let winner = null;
      for (const [addr, amt] of entries) {
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
          contributors = {};
          lastWinner = winner;
          console.log('Payout successful, reset contributors');
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
  return { success: true, message: 'No action' };
}
async function payoutTo(winnerAddress) {
  console.log(`Attempting payout to ${winnerAddress}`);
  if (!runeId || !runeId.includes(':')) {
    console.error(`Payout aborted: runeId invalid (${runeId})`);
    return false;
  }
  try {
    const utxoRes = await fetch(`${baseUrl}/address/${address}/utxos`, { headers });
    if (!utxoRes.ok) throw new Error(`UTXO fetch failed: HTTP ${utxoRes.status}`);
    const utxoResponse = await utxoRes.json();
    const utxos = utxoResponse.data || [];
    if (utxos.length === 0) {
      console.log('No UTXOs');
      return false;
    }
    let totalSats = 0n;
    let hasRune = false;
    utxos.forEach(u => {
      totalSats += BigInt(u.value);
      if (u.runes) u.runes.forEach(r => { if (r.name === runeName) hasRune = true; });
    });
    console.log(`Total sats: ${totalSats}, Has rune: ${hasRune}`);
    if (!hasRune) return false;
    const feeRes = await fetch('https://mempool.space/api/v1/fees/recommended'); // For testnet, use https://mempool.space/testnet/api/...
    if (!feeRes.ok) throw new Error(`Fee fetch failed: HTTP ${feeRes.status}`);
    const fees = await feeRes.json();
    const feeRate = fees.economyFee;
    console.log(`Using fee rate: ${feeRate} sat/vB`);
    const txSize = 10 + utxos.length * 68 + 34 * 3 + 20; // Rough estimate
    let fee = BigInt(feeRate * txSize);
    const dust = 546n;
    let change = totalSats - dust - fee;
    if (change < 0n) {
      console.log('Insufficient sats for fee');
      return false;
    }
    const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin }); // For testnet, use bitcoin.networks.testnet
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network: bitcoin.networks.bitcoin });
    for (const u of utxos) {
      if (!u.outpoint) {
        console.error(`Invalid UTXO: ${JSON.stringify(u)}`);
        continue; // skip bad entry
      }
      const [h, idxStr] = u.outpoint.split(':');
      const script = u.script_pubkey ? Buffer.from(u.script_pubkey, 'hex') : p2wpkh.output;
      psbt.addInput({
        hash: h,
        index: Number(idxStr),
        witnessUtxo: { value: Number(BigInt(u.value)), script }
      });
    }
    psbt.addOutput({ address: winnerAddress, value: Number(dust) });
    let outputIndex = 0; // Always send runes to output 0 (winner)
    if (change >= dust) {
      psbt.addOutput({ address: address, value: Number(change) });
    }
    const [blockStr, txStr] = runeId.split(':');
    const deltaBlock = BigInt(blockStr);
    const deltaTx = BigInt(txStr);
    const amount = 0n; // 0 means all
    const payload = Buffer.concat([
      encodeVarint(0n), // Edicts tag
      encodeVarint(deltaBlock),
      encodeVarint(deltaTx),
      encodeVarint(amount),
      encodeVarint(BigInt(outputIndex))
    ]);
    const opReturnScript = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, bitcoin.opcodes.OP_13, payload]);
    psbt.addOutput({ script: opReturnScript, value: 0 });
    // Wrap BIP32 signer so it returns Buffer (bitcoinjs expects Buffer)
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
    const broadRes = await fetch('https://mempool.space/api/tx', { method: 'POST', body: txHex }); // For testnet, use https://mempool.space/testnet/api/...
    if (broadRes.ok) {
      const txid = await broadRes.text();
      console.log(`Broadcast successful: TXID ${txid}`);
      return true;
    } else {
      console.error(`Broadcast failed: ${await broadRes.text()}`);
      return false;
    }
  } catch (e) {
    console.error('Payout error:', e);
    return false;
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
app.get('/init', async (req, res) => {
  const result = await init();
  if (result.success) {
    res.json({ success: true, runeId, decimals });
  } else {
    res.json(result);
  }
});
app.get('/poll', async (req, res) => {
  const result = await pollActivity();
  res.json(result);
});
app.get('/check', async (req, res) => {
  const result = await checkBlock();
  res.json(result);
});
app.get('/status', async (req, res) => {
  const potRaw = Object.values(contributors).reduce((a, b) => a + b, 0n);
  const pot = (potRaw / (10n ** BigInt(decimals || 0))).toString();
  const contribStr = {};
  for (const k in contributors) contribStr[k] = contributors[k].toString();
  res.json({ address, pot, contributors: contribStr, lastWinner });
});
app.listen(port, () => console.log(`Server running on port ${port}`));