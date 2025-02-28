import { TxHelper, TxModelCreator } from '../helper'
/** 
 * Base Msg
 * @hidden
 */
export class Msg {
  type: string;
  value: any;

  constructor(type:string){
    this.type = type;
  } 

  static getModelClass():any{
    throw new Error("not implement");
  }

  getModel():any{
    throw new Error("not implement");
  }

  pack(): any{
    let msg: any = this.getModel();
    return TxModelCreator.createAnyModel(this.type, msg.serializeBinary());
  }

  /**
   * unpack protobuf tx message
   * @type {[type]}
   * returns protobuf message instance
   */
  unpack(msgValue:string):any{
    if (!msgValue) {
      throw new Error("msgValue can not be empty");
    }
    let msg = (this.constructor as any).getModelClass().deserializeBinary(Buffer.from(msgValue,'base64'));
    if (msg) {
      return msg;
    }else{
      throw new Error("unpack message fail");
    }
  }
}

export enum TxType {
  //bank
  MsgSend ="cosmos.bank.v1beta1.MsgSend",
  MsgMultiSend ="cosmos.bank.v1beta1.MsgMultiSend",
  //staking
  MsgDelegate ="cosmos.staking.v1beta1.MsgDelegate",
  MsgUndelegate ="cosmos.staking.v1beta1.MsgUndelegate",
  MsgBeginRedelegate ="cosmos.staking.v1beta1.MsgBeginRedelegate",
  //distribution
  MsgWithdrawDelegatorReward ="cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward",
  MsgSetWithdrawAddress ="cosmos.distribution.v1beta1.MsgSetWithdrawAddress",
  MsgWithdrawValidatorCommission = "cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission",
  MsgFundCommunityPool = "cosmos.distribution.v1beta1.MsgFundCommunityPool",
  //coinswap
  MsgAddLiquidity ="irismod.coinswap.MsgAddLiquidity",
  MsgRemoveLiquidity ="irismod.coinswap.MsgRemoveLiquidity",
  MsgSwapOrder ="irismod.coinswap.MsgSwapOrder",
  //nft
  MsgIssueDenom ="irismod.nft.MsgIssueDenom",
  MsgTransferNFT ="irismod.nft.MsgTransferNFT",
  MsgEditNFT ="irismod.nft.MsgEditNFT",
  MsgMintNFT ="irismod.nft.MsgMintNFT",
  MsgBurnNFT ="irismod.nft.MsgBurnNFT",
  MsgIssueToken = 'irismod.token.MsgIssueToken',
  MsgEditToken = 'irismod.token.MsgEditToken',
  MsgMintToken = 'irismod.token.MsgMintToken',
  MsgTransferTokenOwner = 'irismod.token.MsgTransferTokenOwner',
  //Contract
  MsgStoreCode = 'wasmd.x.wasmd.v1beta1.MsgStoreCode',
  MsgInstantiateContract = 'wasmd.x.wasmd.v1beta1.MsgInstantiateContract',
  MsgExecuteContract = 'wasmd.x.wasmd.v1beta1.MsgExecuteContract',
  MsgMigrateContract = 'wasmd.x.wasmd.v1beta1.MsgMigrateContract',
  MsgUpdateAdmin = 'wasmd.x.wasmd.v1beta1.MsgUpdateAdmin',
  MsgClearAdmin = 'wasmd.x.wasmd.v1beta1.MsgClearAdmin',
}

/** 
 * Base Tx
 * @hidden
 */
export interface Tx<T extends TxValue> {
  type: string;
  value: T;
}

/** Abstract Tx Value */
export interface TxValue {}

/** 
 * Base Coin
 * @hidden
 */
export interface Coin {
  denom: string;
  amount: string;
}

/** 
 * Base JSONRPCResponse
 * @hidden
 */
export interface JSONRPCResponse<T> {
  jsonrpc: string;
  id:      string;
  error:   JsonRpcError;
  result:  T;
}

/** 
 * JsonRpc Error
 */
export interface JsonRpcError {
  code: number;
  message: string;
  data: string;
}

/** 
 * Base Pubkey
 * @hidden
 */
export interface Pubkey {
  type: PubkeyType;
  value: string;
}

/** 
 * Base Pubkey Type
 * @hidden
 */
export enum PubkeyType {
  secp256k1 = 'secp256k1',
  ed25519 = 'ed25519',//not implement
  sm2 = 'sm2'
}

/** Tag struct */
export interface Tag {
  key: string;
  value: string;
}
