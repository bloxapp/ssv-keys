import { SecretKeyType } from 'bls-eth-wasm';
import bls from '../BLS';

export interface IShares {
    privateKey: string,
    publicKey: string,
    id?: any
}

export interface ISharesKeyPairs {
    validatorPrivateKey: string,
    validatorPublicKey: string,
    shares: IShares[]
}

/**
 * Building threshold for
 * Example of usage:
 *
 *  const threshold: Threshold = new Threshold();
 *  threshold.create('45df68ab75bb7ed1063b7615298e81c1ca1b0c362ef2e93937b7bba9d7c43a94').then((s) => {
 *    console.log(s);
 *  });
 */
class Threshold {
    protected validatorPublicKey: any;
    protected validatorPrivateKey: any;
    protected validatorShares: Array<any> = [];

    static get DEFAULT_SHARES_NUMBER(): number {
      return 4;
    }

    static get DEFAULT_THRESHOLD_NUMBER(): number {
      return 3;
    }

    /**
     * Generate keys and return promise
     */
    async create(privateKey: string, sharesNumber=Threshold.DEFAULT_SHARES_NUMBER, thresholdNumber=Threshold.DEFAULT_THRESHOLD_NUMBER): Promise<ISharesKeyPairs> {
        return new Promise((resolve, reject) => {
            try {
                bls.init(bls.BLS12_381)
                    .then(() => {
                        const msk = [];
                        const mpk = [];

                        // Master key Polynomial
                        this.validatorPrivateKey = bls.deserializeHexStrToSecretKey(privateKey);
                        this.validatorPublicKey = this.validatorPrivateKey.getPublicKey();

                        msk.push(this.validatorPrivateKey);
                        mpk.push(this.validatorPublicKey);

                        // Construct poly
                        for (let i = 1; i < thresholdNumber; i += 1) {
                            const sk: SecretKeyType = new bls.SecretKey();
                            sk.setByCSPRNG();
                            msk.push(sk);
                            const pk = sk.getPublicKey();
                            mpk.push(pk);
                        }

                        // Evaluate shares - starting from 1 because 0 is master key
                        for (let i = 1; i <= sharesNumber; i += 1) {
                            const id = new bls.Id();
                            id.setInt(i + 8);
                            const shareSecretKey = new bls.SecretKey();
                            shareSecretKey.share(msk, id);

                            const sharePublicKey = new bls.PublicKey();
                            sharePublicKey.share(mpk, id);

                            this.validatorShares.push({
                                privateKey: `0x${shareSecretKey.serializeToHexStr()}`,
                                publicKey: `0x${sharePublicKey.serializeToHexStr()}`,
                                id,
                            });
                        }

                        const response: ISharesKeyPairs = {
                            validatorPrivateKey: `0x${this.validatorPrivateKey.serializeToHexStr()}`,
                            validatorPublicKey: `0x${this.validatorPublicKey.serializeToHexStr()}`,
                            shares: this.validatorShares,
                        };
                        resolve(response);
                    });
            } catch (error: any) {
                reject(error);
            }
        });
    }
}

export default Threshold;
