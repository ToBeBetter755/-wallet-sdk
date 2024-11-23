import { bufferToBinaryString, normalize, salt } from "@/utils";
// 从 utils 工具库中导入 bufferToBinaryString（将缓冲区转换为二进制字符串）、normalize（将字符串规范化为NFKD格式,消除unicode编码的平台差异性）和 salt（生成盐值）函数。

import { pbkdf2 } from '@noble/hashes/pbkdf2';
// 导入 noble/hashes 库中的 pbkdf2 函数，使用HMAC作为核心算法，根据用户提供的密码、盐值（salt）、迭代次数和派生密钥的长度，生成一个固定长度的密钥。

import { sha512 } from '@noble/hashes/sha2';
// 导入 noble/hashes 库中的 sha512 函数，用于计算 SHA-512 哈希值。

import * as bip39 from 'bip39';
// 导入 bip39 库，提供 BIP-39 助记词相关的功能，如单词列表和工具方法。

import * as crypto from 'crypto';
// 导入 Node.js 的 crypto 模块，用于生成随机字节和计算哈希值。

import { Buffer } from "node:buffer";
// 导入 Node.js 的 Buffer 类，用于处理二进制数据。

const mnemonicLength = [12, 15, 18, 21, 24];
// 定义一个数组，表示支持的助记词长度（12、15、18、21、24个单词）。

/**
 * 生成助记词
 * @param length - 指定助记词长度
 */
export function generateMnemonic(length: number = 12): { phrase: string[], wordList: string[] } {
    // 如果输入的长度不在支持的范围内，抛出异常
    if (!mnemonicLength.includes(length)) throw "length必须包含在" + mnemonicLength;

    // 1. 根据助记词长度生成随机熵（entropy），长度为 (length * 11 - length / 3) / 8 字节
    const entropy = crypto.randomBytes((length * 11 - length / 3) / 8);
    // console.log(bufferToBinaryString(entropy, "")); // 打印生成的熵的二进制格式

    // 2. 使用 SHA-256 计算熵的哈希值
    const hash = crypto.createHash('sha256').update(entropy).digest();
    // console.log(bufferToBinaryString(hash, " ")); // 打印SHA-256哈希值的二进制格式

    // 取哈希值的前 length / 3 位作为校验和，右移丢弃多余位
    const checksum = hash[0] >> length / 3;

    // 将校验和转换为二进制字符串，前导零补齐
    const checksumBinary = checksum.toString(2).padStart(length / 3, '0');
    // console.log(checksumBinary)

    // 3. 将熵和校验和组合成完整的二进制字符串
    let bits = bufferToBinaryString(entropy) + checksumBinary;

    // 4. 将二进制字符串按每11位分割为索引
    const indices = [];
    for (let i = 0; i < bits.length; i += 11) {
        // 每11位转为十进制数，存入 indices 数组
        const index = parseInt(bits.slice(i, i + 11), 2);
        indices.push(index);
    }

    // 5. 将索引映射到 BIP-39 单词列表生成助记词
    return {
        phrase: indices.map(index => bip39.wordlists.english[index]), // 映射助记词单词
        wordList: bip39.wordlists.english // 返回 BIP-39 的完整单词列表
    };
}

/**
 * 验证助记词
 * @param mnemonic - 需要验证的助记词（字符串数组）
 */
export function validateMnemonic(mnemonic: string[]): boolean {
    // 1. 检查助记词的长度是否有效
    if (!mnemonicLength.includes(mnemonic.length)) return false;

    // 2. 检查助记词中的单词是否都在 BIP-39 的词汇表中
    if (!mnemonic.every(word => bip39.wordlists.english.includes(word))) return false;

    // 3. 将助记词转换为二进制位串
    const bits = mnemonic.map(word => bip39.wordlists.english.indexOf(word).toString(2).padStart(11, '0')).join('');

    // 4. 提取种子位和校验和位
    const seedBitsLength = (mnemonic.length * 11) - (mnemonic.length / 3); // 计算种子位长度
    const seedBits = bits.slice(0, seedBitsLength); // 种子位
    const checksumBits = bits.slice(seedBitsLength); // 校验和位

    // 5. 使用种子位生成熵，并计算校验和
    const entropy = Buffer.from(seedBits.match(/.{1,8}/g)!.map(byte => parseInt(byte, 2))); // 将种子位转为 Buffer
    const hash = crypto.createHash('sha256').update(entropy).digest(); // 计算熵的哈希值
    const checksum = hash[0] >> mnemonic.length / 3; // 取校验和

    // 比较校验和是否匹配，返回结果
    return checksumBits === checksum.toString(2).padStart((mnemonic.length / 3), '0');
}

/**
 * 根据助记词生成种子
 * @param m - 助记词（字符串数组或用空格分隔的字符串）
 * @param password - 可选的密码短语，用于生成种子
 */
export function generateSeed(m: string[] | string, password: string = ""): Buffer {
    // 如果是数组，拼接为字符串；否则直接使用
    const mnemonic = Array.isArray(m) ? m.join(' ') : m;
    // 将助记词标准化并转换为字节数组
    const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
    // 将密码标准化生成盐值字节数组
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));

    // 使用 PBKDF2 算法，根据助记词和盐值派生密钥
    const res = pbkdf2(sha512, mnemonicBuffer, saltBuffer, {
        c: 2048, // 迭代次数为 2048
        dkLen: 64, // 派生密钥长度为 64 字节
    });

    // 返回生成的种子（Buffer 格式）
    return Buffer.from(res);
}