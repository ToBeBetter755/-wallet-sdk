import {Buffer} from "node:buffer";

/**
 * 将 Buffer 对象转换为二进制字符串格式
 * @param {Buffer} buffer - 要转换的 Buffer 对象
 * @param {string} [separator=""] - 二进制字符串之间的分隔符
 * @returns {string} - 转换后的二进制字符串
 */
export function bufferToBinaryString(buffer: Buffer, separator: string = ""): string {
    return Array.from(buffer)
        .map((byte) => byte.toString(2).padStart(8, '0')) // 将每个字节转换为8位二进制字符串，前导零填充
        .join(separator); // 使用指定的分隔符连接二进制字符串
}


/**
 * 将字符串规范化为NFKD格式,消除unicode编码的平台差异性
 * @param {string} str - 要规范化的字符串
 * @returns {string} - 规范化后的字符串
 */
export function normalize(str: string) {
    return (str || '').normalize('NFKD');
}

/**
 * 生成盐值
 * @param password
 */
export function salt(password: string) {
    return 'mnemonic' + (password || '');
}