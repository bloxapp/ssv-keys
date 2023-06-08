import * as ethers from 'ethers';

import {
  IsOptional,
  ValidateNested,
  validateSync
} from 'class-validator';

import * as web3Helper from '../helpers/web3.helper';

import { KeySharesData } from './KeySharesData/KeySharesData';
import { KeySharesPayload } from './KeySharesData/KeySharesPayload';
import { EncryptShare } from '../Encryption/Encryption';
import { IKeySharesPartitialData } from './KeySharesData/IKeySharesData';
import { IOperator } from './KeySharesData/IOperator';
import { operatorSortedList } from '../helpers/operator.helper';
import { OwnerAddressFormatError, RegisterNonceFormatError } from '../exceptions/keystore';

export interface IKeySharesPayloadData {
  publicKey: string,
  operators: IOperator[],
  encryptedShares: EncryptShare[],
}

export interface IKeySharesToSignatureData {
  ownerAddress: string,
  registerNonce: number,
  privateKey: string,
}

export interface IKeySharesFromSignatureData {
  ownerAddress: string,
  registerNonce: number,
  publicKey: string,
}

const SIGNATURE_LENGHT = 192;
const PUBLIC_KEY_LENGHT = 96;

/**
 * Key shares file data interface.
 */
export class KeyShares {
  @IsOptional()
  @ValidateNested()
  public data: KeySharesData;

  @IsOptional()
  @ValidateNested()
  public payload: KeySharesPayload;

  constructor() {
    this.data = new KeySharesData();
    this.payload = new KeySharesPayload();
  }

  /**
   * Build payload from operators list, encrypted shares and validator public key
   * @param publicKey
   * @param operatorIds
   * @param encryptedShares
   */
  async buildPayload(metaData: IKeySharesPayloadData, toSignatureData: IKeySharesToSignatureData): Promise<any> {
    const {
      ownerAddress,
      registerNonce,
      privateKey,
    } = toSignatureData;

    if (!Number.isInteger(registerNonce) || registerNonce < 0) {
      throw new RegisterNonceFormatError(registerNonce, 'Owner nonce is not positive integer');
    }

    let address;
    try {
      address = web3Helper.web3.utils.toChecksumAddress(ownerAddress);
    } catch {
      throw new OwnerAddressFormatError(ownerAddress, 'Owner address is not a valid Ethereum address');
    }

    const payload = this.payload.build({
      publicKey: metaData.publicKey,
      operatorIds: operatorSortedList(metaData.operators).map(operator => operator.id),
      encryptedShares: metaData.encryptedShares,
    });

    const signature = await web3Helper.buildSignature(`${address}:${registerNonce}`, privateKey);
    const signSharesBytes = web3Helper.hexArrayToBytes([signature, payload.sharesData]);

    payload.sharesData = `0x${signSharesBytes.toString('hex')}`;

    // verify signature
    await this.validateSingleShares(payload.sharesData, {
      ownerAddress,
      registerNonce,
      publicKey: await web3Helper.privateToPublicKey(privateKey),
    });

    return payload;
  }


  async validateSingleShares(shares: string, fromSignatureData: IKeySharesFromSignatureData): Promise<void> {
    const {
      ownerAddress,
      registerNonce,
      publicKey,
    } = fromSignatureData;

    if (!Number.isInteger(registerNonce) || registerNonce < 0) {
      throw new RegisterNonceFormatError(registerNonce, 'Owner nonce is not positive integer');
    }

    let address;
    try {
      address = web3Helper.web3.utils.toChecksumAddress(ownerAddress);
    } catch {
      throw new OwnerAddressFormatError(ownerAddress, 'Owner address is not a valid Ethereum address');
    }

    const signaturePt = shares.replace('0x', '').substring(0, SIGNATURE_LENGHT);

    await web3Helper.validateSignature(`${address}:${registerNonce}`, `0x${signaturePt}`, publicKey);
  }

  /**
   * Build shares from bytes string and operators list length
   * @param bytes
   * @param operatorCount
   */
  buildSharesFromBytes(bytes: string, operatorCount: number): any {
    const sharesPt = bytes.replace('0x', '').substring(SIGNATURE_LENGHT);

    const pkSplit = sharesPt.substring(0, operatorCount * PUBLIC_KEY_LENGHT);
    const pkArray = ethers.utils.arrayify('0x' + pkSplit);
    const sharesPublicKeys = this._splitArray(operatorCount, pkArray).map(item =>
      ethers.utils.hexlify(item),
    );

    const eSplit = bytes.substring(operatorCount * PUBLIC_KEY_LENGHT);
    const eArray = ethers.utils.arrayify('0x' + eSplit);
    const encryptedKeys = this._splitArray(operatorCount, eArray).map(item =>
      Buffer.from(ethers.utils.hexlify(item).replace('0x', ''), 'hex').toString(
        'base64',
      ),
    );
    return {
      sharesPublicKeys,
      encryptedKeys,
    };
  }

  /**
   * Set new data and validate it.
   * @param data
   */
  update(data: IKeySharesPartitialData) {
    this.data.update(data);
    this.validate();
  }

  /**
   * Validate everything
   */
  validate(): any {
    validateSync(this);
  }

  /**
   * Initialise from JSON or object data.
   */
  fromJson(content: string | any): KeyShares {
    const data = typeof content === 'string'
      ? JSON.parse(content).data
      : content.data;

    this.update(data);
    return this;
  }

  /**
   * Stringify key shares to be ready for saving in file.
   */
  toJson(): string {
    return JSON.stringify({
      version: 'v4',
      createdAt: new Date().toISOString(),
      data: this.data || null,
      payload: this.payload.readable || null,
    }, null, '  ');
  }

  private _splitArray(parts: number, arr: Uint8Array) {
    const partLength = Math.floor(arr.length / parts);
    const partsArr = [];
    for (let i = 0; i < parts; i++) {
      const start = i * partLength;
      const end = start + partLength;
      partsArr.push(arr.slice(start, end));
    }
    return partsArr;
  }
}
