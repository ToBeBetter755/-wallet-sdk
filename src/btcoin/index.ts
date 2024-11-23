import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import {BIP32Factory} from "bip32";
import {Payment, Transaction} from "bitcoinjs-lib";

const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

/**
 * 根据seed生成地址
 * @param props
 */
export function generateAddressBySeed(props: {
    seedHex: Buffer;
    isReceive: boolean;
    addressIndex: number;
    network: keyof typeof bitcoin.networks;
    method: string;
}): Payment {
    const {seedHex, isReceive, addressIndex, network, method} = props
    const path = `m/44'/0'/0'/${isReceive ? 0 : 1}/${addressIndex}`;
    const root = bip32.fromSeed(seedHex)
    const child = root.derivePath(path)
    switch (method) {
        case 'p2pkh':
            return bitcoin.payments.p2pkh({pubkey: child.publicKey, network: bitcoin.networks[network],})
        case 'p2wpkh':
            return bitcoin.payments.p2wpkh({pubkey: child.publicKey, network: bitcoin.networks[network],})
        // case 'p2sh':
        default:
            return bitcoin.payments.p2sh({
                redeem: bitcoin.payments.p2wpkh({
                    pubkey: child.publicKey,
                    network: bitcoin.networks[network],
                })
            })
    }
}

/**
 * 多签名地址
 */
export function createMultiSignAddress(props: {
    pubkeys: Buffer[];
    network: keyof typeof bitcoin.networks;
    method: string;
    threshold: number
}): Payment {
    const {pubkeys, network, method, threshold: m} = props;
    const opts = {pubkeys, m, network: bitcoin.networks[network],}
    switch (method) {
        case 'p2wsh':
            return bitcoin.payments.p2wsh({redeem: bitcoin.payments.p2ms(opts)});
        // case 'p2sh':
        default:
            return bitcoin.payments.p2sh({redeem: bitcoin.payments.p2wsh({redeem: bitcoin.payments.p2ms(opts)}),})
    }
}

export const toXOnly = (pubKey: Buffer) =>
    pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);

/**
 * taproot地址
 */
export function createTaprootAddress(props: {
    seedHex: Buffer;
    isReceive: boolean;
    addressIndex: number;
    network: keyof typeof bitcoin.networks;
}): Payment {
    const {seedHex, isReceive, addressIndex, network} = props
    const root = bip32.fromSeed(seedHex);
    const path = `m/44'/0'/0'/${isReceive ? 0 : 1}/${addressIndex}`;
    const child = root.derivePath(path)
    const internalPubkey = toXOnly(child.publicKey);
    return bitcoin.payments.p2tr({
        internalPubkey,
    });
}

export function fromRaw(raw: any, noWitness?: boolean): Transaction {
    const tx = new Transaction();
    tx.version = raw.version;
    tx.locktime = raw.locktime;

    raw.ins.forEach((txIn: any, i: number) => {
        const txHash = Buffer.from(txIn.hash, 'hex');
        let scriptSig;

        if (txIn.data) {
            scriptSig = Buffer.from(txIn.data, 'hex');
        } else if (txIn.script) {
            scriptSig = bitcoin.script.fromASM(txIn.script);
        }

        tx.addInput(txHash, txIn.index, txIn.sequence, scriptSig);

        if (!noWitness && txIn.witness) {
            const witness = txIn.witness.map((x: string) => {
                return Buffer.from(x, 'hex');
            });

            tx.setWitness(i, witness);
        }
    });

    raw.outs.forEach((txOut: any) => {
        let script: Buffer;

        if (txOut.data) {
            script = Buffer.from(txOut.data, 'hex');
        } else if (txOut.script) {
            script = bitcoin.script.fromASM(txOut.script);
        }

        tx.addOutput(script!, txOut.value);
    });

    return tx;
}
