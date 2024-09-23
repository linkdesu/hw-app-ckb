import Transport from "@ledgerhq/hw-transport";
import BIPPath from "bip32-path";
import Blake2b from "blake2b-wasm";
import { bech32m } from "bech32";

// CKB address is longer than the longest Bitcoin address
// The bech32m encoding limit should be increased
const BECH32_LIMIT = 1023;

function pathToBuffer(path: string) {
  const bipPath = BIPPath.fromString(path).toPathArray();
  const data = Buffer.alloc(1 + bipPath.length * 4);
  data.writeUInt8(bipPath.length, 0);
  bipPath.forEach((segment, index) => {
    data.writeUInt32BE(segment, 1 + index * 4);
  });
  return data;
}

/**
 * Nervos API
 *
 * @example
 * import Ckb from "@obsidiansystems/hw-app-ckb";
 * const ckb = new Ckb(transport);
 */
export default class Ckb {
  transport: Transport;

  constructor(transport: Transport, scrambleKey: string = "CKB") {
    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      [
        "getAppConfiguration",
        "getWalletId",
        "getWalletPublicKey",
        "signAnnotatedTransaction",
      ],
      scrambleKey
    );
  }

  /**
   * get CKB address for a given BIP 32 path.
   *
   * @param path a path in BIP 32 format
   * @return an object with a publicKey, lockArg, and (secp256k1+blake160) address.
   * @example
   * const result = await ckb.getWalletPublicKey("44'/144'/0'/0/0");
   * const publicKey = result.publicKey;
   * const lockArg = result.lockArg;
   * const address = result.address;
   */
  async getWalletPublicKey(path: string, testnet: boolean) {
    const cla = 0x80;
    const ins = 0x02;
    const p1 = 0x00;
    const p2 = 0x00;
    const pathBuf = pathToBuffer(path);

    const response = await this.transport.send(cla, ins, p1, p2, pathBuf);

    const publicKeyLength = response[0];
    const publicKey = response.slice(1, 1 + publicKeyLength);

    const compressedPublicKey = Buffer.alloc(33);
    compressedPublicKey.fill(publicKey[64] & 1 ? "03" : "02", 0, 1, "hex");
    compressedPublicKey.fill(publicKey.subarray(1, 33), 1, 33);
    const hashPersonalization = Uint8Array.from([99, 107, 98, 45, 100, 101, 102, 97, 117, 108, 116, 45, 104, 97, 115, 104]);
    const lockArg = Buffer.from(
      Blake2b(32, null, null, hashPersonalization)
        .update(compressedPublicKey)
        .digest("binary")
        .subarray(0, 20)
    );

    const addr_contents: number[] = [
      // CKB 2021 address full format prefix
      0x00,
      // SECP256K1_BLAKE160 code hash
      ...[
        155, 215, 224, 111,  62, 207, 75,
        224, 242, 252, 210,  24, 139, 35,
        241, 185, 252, 200, 142,  93, 75,
        101, 168,  99, 123,  23, 114, 59,
        189, 163, 204, 232
      ],
      // SECP256K1_BLAKE160 hash type
      0b00000001,
      // lock args
      ...Array.from(lockArg)
    ];
    const addr = bech32m.encode(
      testnet ? "ckt" : "ckb",
      bech32m.toWords(addr_contents),
      BECH32_LIMIT
    );

    return {
      publicKey: publicKey.toString("hex"),
      lockArg: lockArg.toString("hex"),
      address: addr,
    };
  }

  /**
   * get extended public key for a given BIP 32 path.
   *
   * @param path a path in BIP 32 format
   * @return an object with a publicKey
   * @example
   * const result = await ckb.getWalletPublicKey("44'/144'/0'/0/0");
   * const publicKey = result;
   */
  async getWalletExtendedPublicKey(path: string) {
    const bipPath = BIPPath.fromString(path).toPathArray();

    const cla = 0x80;
    const ins = 0x04;
    const p1 = 0x00;
    const p2 = 0x00;
    const data = Buffer.alloc(1 + bipPath.length * 4);

    data.writeUInt8(bipPath.length, 0);
    bipPath.forEach((segment, index) => {
      data.writeUInt32BE(segment, 1 + index * 4);
    });

    const response = await this.transport.send(cla, ins, p1, p2, data);
    const publicKeyLength = response[0];
    const chainCodeOffset = 2 + publicKeyLength;
    const chainCodeLength = response[1 + publicKeyLength];
    return {
      public_key: response.slice(1, 1 + publicKeyLength).toString("hex"),
      chain_code: response
        .slice(chainCodeOffset, chainCodeOffset + chainCodeLength)
        .toString("hex"),
    };
  }

  /**
   * Get the version of the Nervos app installed on the hardware device
   *
   * @return an object with a version
   * @example
   * const result = await ckb.getAppConfiguration();
   *
   * {
   *   "version": "1.0.3",
   *   "hash": "0000000000000000000000000000000000000000"
   * }
   */
  async getAppConfiguration(): Promise<{
    version: string,
    hash: string,
  }> {
    const response1 = await this.transport.send(0x80, 0x00, 0x00, 0x00);
    const response2 = await this.transport.send(0x80, 0x09, 0x00, 0x00);
    return {
      version: "" + response1[0] + "." + response1[1] + "." + response1[2],
      hash: response2.slice(0, -3).toString("latin1") // last 3 bytes should be 0x009000
    };
  }

  /**
   * Get the wallet identifier for the Ledger wallet
   *
   * @return a byte string
   * @example
   * const id = await ckb.getWalletId();
   *
   * "0x69c46b6dd072a2693378ef4f5f35dcd82f826dc1fdcc891255db5870f54b06e6"
   */
  async getWalletId(): Promise<string> {
    const response = await this.transport.send(0x80, 0x01, 0x00, 0x00);

    const result = response.slice(0, 32).toString("hex");

    return result;
  }

  async signMessage(
    path: string,
    rawMsgHex: string,
    displayHex: boolean
  ): Promise<string> {
    const bipPath = BIPPath.fromString(path).toPathArray();
    const magicBytes = Buffer.from("Nervos Message:");
    const rawMsg = Buffer.concat([magicBytes, Buffer.from(rawMsgHex, "hex")]);

    //Init apdu
    let rawPath = Buffer.alloc(1 + 1 + bipPath.length * 4);
    rawPath.writeInt8(displayHex ? 1 : 0, 0);
    rawPath.writeInt8(bipPath.length, 1);
    bipPath.forEach((segment, index) => {
      rawPath.writeUInt32BE(segment, 2 + index * 4);
    });
    await this.transport.send(0x80, 0x06, 0x00, 0x00, rawPath);

    // Msg Chunking
    const maxApduSize = 230;
    let txFullChunks = Math.floor(rawMsg.length / maxApduSize);
    for (let i = 0; i < txFullChunks; i++) {
      let data = rawMsg.slice(i*maxApduSize, (i+1)*maxApduSize);
      await this.transport.send(0x80, 0x06, 0x01, 0x00, data);
    }

    let lastOffset = Math.floor(rawMsg.length / maxApduSize) * maxApduSize;
    let lastData = rawMsg.slice(lastOffset, lastOffset+maxApduSize);
    let response = await this.transport.send(0x80, 0x06, 0x81, 0x00, lastData);
    return response.slice(0,65).toString("hex");
  }

  async signMessageHash(
    path: string,
    rawMsgHex: string,
  ): Promise<string> {
    const rawMsg = Buffer.from(rawMsgHex, "hex");
    let pathBuf = pathToBuffer(path);
    await this.transport.send(0x80, 0x07, 0x00, 0x00, pathBuf);
    let response = await this.transport.send(0x80, 0x07, 0x80, 0x00, rawMsg);

    return response.slice(0,65).toString("hex");
  }
}

