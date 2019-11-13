import BigNumber from 'bignumber.js'
import { GasPriceMinimum } from '../generated/types/GasPriceMinimum'
import { BaseWrapper, proxyCall, valueToBigNumber } from './BaseWrapper'

export interface GasPriceMinimumConfig {
  gasPriceMinimum: BigNumber
  targetDensity: BigNumber
  adjustmentSpeed: BigNumber
  proposerFraction: BigNumber
}

/**
 * Stores the gas price minimum
 */
export class GasPriceMinimumWrapper extends BaseWrapper<GasPriceMinimum> {
  /**
   * Query current gas price minimum.
   * @returns current gas price minimum in the requested currency
   */
  gasPriceMinimum = proxyCall(this.contract.methods.gasPriceMinimum, undefined, valueToBigNumber)
  /**
   * Query target density parameter.
   * @returns the current block density targeted by the gas price minimum algorithm.
   */
  targetDensity = proxyCall(this.contract.methods.targetDensity, undefined, valueToBigNumber)
  /**
   * Query adjustment speed parameter
   * @returns multiplier that impacts how quickly gas price minimum is adjusted.
   */
  adjustmentSpeed = proxyCall(this.contract.methods.adjustmentSpeed, undefined, valueToBigNumber)
  /**
   * Query infrastructure fraction parameter.
   * @returns current fraction of the gas price minimum which is sent to
   * the infrastructure fund
   */
  proposerFraction = proxyCall(this.contract.methods.proposerFraction, undefined, valueToBigNumber)
  /**
   * Returns current configuration parameters.
   */
  async getConfig(): Promise<GasPriceMinimumConfig> {
    const res = await Promise.all([
      this.gasPriceMinimum(),
      this.targetDensity(),
      this.adjustmentSpeed(),
      this.proposerFraction(),
    ])
    return {
      gasPriceMinimum: res[0],
      targetDensity: res[1],
      adjustmentSpeed: res[2],
      proposerFraction: res[3],
    }
  }
}
