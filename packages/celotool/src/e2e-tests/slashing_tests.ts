// tslint:disable-next-line: no-reference (Required to make this work w/ ts-node)
/// <reference path="../../../contractkit/types/web3.d.ts" />

import { ContractKit, newKit, newKitFromWeb3 } from '@celo/contractkit'
import { NULL_ADDRESS } from '@celo/utils/lib/address'
import BigNumber from 'bignumber.js'
import { assert } from 'chai'
import * as rlp from 'rlp'
import Web3 from 'web3'
import { getHooks, GethTestConfig, sleep } from './utils'
import { getContext, GethInstanceConfig, initAndStartGeth, waitToFinishSyncing } from './utils'

/*interface IstanbulAggregatedSeal {
  bitmap: number,
  signature: string,
  round: number,
}

interface IstanbulExtraData {
  addedValidators: string[],
  addedValidatorsPublicKeys: string[]
  removedValidators: number,
  seal: IstanbulAggregatedSeal,
  aggregatedSeal: IstanbulAggregatedSeal,
  parentAggregatedSeal: string,
  epochData: string,
}*/

describe('Slashing tests', function(this: any) {
  this.timeout(0)

  let kit: ContractKit
  let accounts: any
  let validators: any

  const gethConfig: GethTestConfig = {
    migrateTo: 18,
    instances: [
      { name: 'validator0', validating: true, syncmode: 'full', port: 30303, rpcport: 8545 },
      { name: 'validator1', validating: true, syncmode: 'full', port: 30305, rpcport: 8547 },
      { name: 'validator2', validating: true, syncmode: 'full', port: 30307, rpcport: 8549 },
    ],
  }

  const gethConfigDown = {
    migrate: true,
    instances: [
      // Validators 0 and 1 are swapped in and out of the group.
      { name: 'validator0', validating: true, syncmode: 'full', port: 30303, rpcport: 8545 },
      { name: 'validator1', validating: true, syncmode: 'full', port: 30305, rpcport: 8547 },
      // Validator 2 will authorize a validating key every other epoch.
      { name: 'validator2', validating: true, syncmode: 'full', port: 30307, rpcport: 8549 },
      { name: 'validator3', validating: true, syncmode: 'full', port: 30309, rpcport: 8551 },
    ],
  }

  const context: any = getContext(gethConfig)
  const contextDown: any = getContext(gethConfigDown)
  const hooks = getHooks(gethConfig)
  before(hooks.before)
  after(hooks.after)

  const validatorAddress: string = '0x47e172f6cfb6c7d01c1574fa3e2be7cc73269d95'

  const restartGeth = async () => {
    // Restart the validator node
    await hooks.restart()

    // TODO(mcortesi): magic sleep. without it unlockAccount sometimes fails
    await sleep(2)
    kit = newKit('http://localhost:8545')
    await kit.web3.eth.personal.unlockAccount(validatorAddress, '', 1000)
    validators = await kit._web3Contracts.getValidators()
    accounts = await kit._web3Contracts.getAccounts()
  }

  const restartWithDowntime = async () => {
    await contextDown.hooks.restart()
    web3 = new Web3('http://localhost:8545')
    kit = newKitFromWeb3(web3)
    console.log(await web3.eth.getAccounts())
    goldToken = await kit._web3Contracts.getGoldToken()
    stableToken = await kit._web3Contracts.getStableToken()
    sortedOracles = await kit._web3Contracts.getSortedOracles()
    validators = await kit._web3Contracts.getValidators()
    registry = await kit._web3Contracts.getRegistry()
    reserve = await kit._web3Contracts.getReserve()
    election = await kit._web3Contracts.getElection()
    epochRewards = await kit._web3Contracts.getEpochRewards()
    accounts = await kit._web3Contracts.getAccounts()
  }

  const waitForEpochTransition = async (epoch: number) => {
    let blockNumber: number
    do {
      blockNumber = await kit.web3.eth.getBlockNumber()
      await sleep(0.1)
    } while (blockNumber % epoch !== 1)
  }

  const waitUntilBlock = async (bn: number) => {
    let blockNumber: number
    do {
      blockNumber = await web3.eth.getBlockNumber()
      await sleep(0.1)
    } while (blockNumber < bn)
  }

  const getValidatorGroupMembers = async (blockNumber?: number) => {
    if (blockNumber) {
      const [groupAddress] = await validators.methods
        .getRegisteredValidatorGroups()
        .call({}, blockNumber)
      const groupInfo = await validators.methods
        .getValidatorGroup(groupAddress)
        .call({}, blockNumber)
      return groupInfo[0]
    } else {
      const [groupAddress] = await validators.methods.getRegisteredValidatorGroups().call()
      const groupInfo = await validators.methods.getValidatorGroup(groupAddress).call()
      return groupInfo[0]
    }
  }

  const getValidatorGroupPrivateKey = async () => {
    console.info('start1')
    const [groupAddress] = await validators.methods.getRegisteredValidatorGroups().call()
    console.info('start2 ' + groupAddress)
    const name = await accounts.methods.getName(groupAddress).call()
    console.info('start3 ' + name)
    const encryptedKeystore64 = name.split(' ')[1]
    const encryptedKeystore = JSON.parse(Buffer.from(encryptedKeystore64, 'base64').toString())
    console.info('start4 ' + name)
    // The validator group ID is the validator group keystore encrypted with validator 0's
    // private key.
    // @ts-ignore
    const encryptionKey = `0x${gethConfig.instances[0].privateKey}`
    const decryptedKeystore = kit.web3.eth.accounts.decrypt(encryptedKeystore, encryptionKey)
    console.info('start5 ' + name)
    return decryptedKeystore.privateKey
  }

  describe('when running a network', () => {
    before(async () => {
      await restartGeth()
    })

    it('should have registered validators', async () => {
      console.info('helo-1')
      const groupPrivateKey = await getValidatorGroupPrivateKey()
      console.info('helo-2')
      const additionalNodes: GethInstanceConfig[] = [
        {
          name: 'validatorGroup',
          validating: false,
          syncmode: 'full',
          port: 30313,
          wsport: 8555,
          rpcport: 8557,
          privateKey: groupPrivateKey.slice(2),
          peers: [8545],
        },
      ]
      console.info('helo-3')
      await Promise.all(
        additionalNodes.map((nodeConfig) =>
          initAndStartGeth(context.hooks.gethBinaryPath, nodeConfig)
        )
      )
      console.info('helo-4')

      const epoch = new BigNumber(await validators.methods.getEpochSize().call()).toNumber()
      console.info('Epoch size: ' + epoch)

      const validatorAccounts = await getValidatorGroupMembers()
      assert.equal(validatorAccounts.length, 3)

      // Wait for an epoch transition so we can activate our vote.
      await waitForEpochTransition(epoch)

      // Prepare for slashing.
      const groupWeb3 = new Web3('ws://localhost:8555')
      await waitToFinishSyncing(groupWeb3)
      const groupKit = newKitFromWeb3(groupWeb3)
      const group: string = (await groupWeb3.eth.getAccounts())[0]
      const txos = await (await groupKit.contracts.getElection()).activate(group)
      for (const txo of txos) {
        await txo.sendAndWaitForReceipt({ from: group })
      }

      // Wait for an extra epoch transition to ensure everyone is connected to one another.
      await waitForEpochTransition(epoch)

      const validatorsWrapper = await kit.contracts.getValidators()
      const validatorList = await validatorsWrapper.getRegisteredValidators()
      assert.equal(true, validatorList.length > 0)
    })

    it('should parse blockNumber from test header', async () => {
      this.timeout(0)
      const contract = await kit._web3Contracts.getElection()
      const header = kit.web3.utils.hexToBytes(
        '0xf901f9a07285abd5b24742f184ad676e31f6054663b3529bc35ea2fcad8a3e0f642a46f7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ecc60e00b3fe5ce9f6e1a10e5469764daf51f1fe93c22ec3f9a7583a80357217a0d35d334d87c0cc0a202e3756bf81fae08b1575f286c7ee7a3f8df4f0f3afc55da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302000001832fefd8825208845c47775c80a00000000000000000000000000000000000000000000000000000000000000000880000000000000000'
      )
      const blockNumber = await contract.methods.getBlockNumberFromHeader(header).call()
      assert.equal(blockNumber, 1)
    })

    it('should parse blockNumber from current header', async () => {
      const contract = await kit._web3Contracts.getElection()
      const current = await kit.web3.eth.getBlockNumber()
      const block = await kit.web3.eth.getBlock(current)
      const rlpEncodedBlock = rlp.encode(headerArray(kit.web3, block))
      const blockNumber = await contract.methods.getBlockNumberFromHeader(rlpEncodedBlock).call()
      assert.equal(blockNumber, current)
    })

    it('should hash test header correctly', async () => {
      const contract = await kit._web3Contracts.getElection()
      const header = kit.web3.utils.hexToBytes(
        '0xf901f9a07285abd5b24742f184ad676e31f6054663b3529bc35ea2fcad8a3e0f642a46f7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ecc60e00b3fe5ce9f6e1a10e5469764daf51f1fe93c22ec3f9a7583a80357217a0d35d334d87c0cc0a202e3756bf81fae08b1575f286c7ee7a3f8df4f0f3afc55da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302000001832fefd8825208845c47775c80a00000000000000000000000000000000000000000000000000000000000000000880000000000000000'
      )
      const hash = await contract.methods.hashHeader(header).call()
      assert.equal(hash, '0xf5a450266c77dce47f7698959d8e7019db860ee19a5322b16a853fdf23607100')
    })

    it('should hash current header correctly', async () => {
      const contract = await kit._web3Contracts.getElection()
      const current = await kit.web3.eth.getBlockNumber()
      const block = await kit.web3.eth.getBlock(current)
      const rlpEncodedBlock = rlp.encode(headerArray(kit.web3, block))
      const blockHash = await contract.methods.hashHeader(rlpEncodedBlock).call()
      assert.equal(blockHash, block.hash)
    })

    it('slashing for double signing', async () => {
      const contract = await kit._web3Contracts.getElection()
      const current = await kit.web3.eth.getBlockNumber()
      const block = await kit.web3.eth.getBlock(current)
      //const blockIstanbulData = rlp.decode(block.extraData)
      //const parentAggregatedSeal = blockIstanbulData[5]

      const doubleSignedBlock = await kit.web3.eth.getBlock(current)
      doubleSignedBlock.timestamp++

      // aggregateSeal = aggregateSeal(validator0.sign(doubleSignedBlock), validator1.sign(doubleSignedBlock))
      // seal = validatorAddress.sign()

      // doubleSignedBlock.extraData = istanbulExtraDataArray({
      //   seal,                   // the ECDSA signature by the proposer
      //   aggregatedSeal,         // the aggregated BLS signature created via IBFT consensus.
      //   parentAggregatedSeal }) // the aggregated BLS signature for the previous block.

      const rlpEncodedBlock = rlp.encode(headerArray(kit.web3, block))
      const rlpEncodedDoubleSignedBlock = rlp.encode(headerArray(kit.web3, doubleSignedBlock))
      const blockHash = await contract.methods.hashHeader(rlpEncodedBlock).call()
      const doubleSignedBlockHash = await contract.methods
        .hashHeader(rlpEncodedDoubleSignedBlock)
        .call()
      console.info('Canonical block hash (blockNumber ' + current + '): ' + blockHash)
      console.info(
        'Double signed block hash (blockNumber  ' + current + '): ' + doubleSignedBlockHash
      )
      const validators = await kit.contracts.getValidators()
      const validatorList = await validators.getRegisteredValidators()
      for (const validator of validatorList) {
        console.info(validator)
      }
      console.info('end')

      // const slasher = await kit.contracts.getDoubleSigningSlasher()
      // slasher.checkForDoubleSigning(
      //   signer, // The signer to be slashed.
      //   index,  // Validator index at the block.
      //   blockA, // First double signed block.
      //   blockB, // Second double signed block.
      //   Block)  // number where double signing occured. Throws if no double signing is detected.
    })
  })

  let doubleSigningBlock: any

  describe('test slashing for downtime', () => {
    before(async function(this: any) {
      this.timeout(0) // Disable test timeout
      await restartWithDowntime()

      try {
        const elect = await kit._web3Contracts.getElection()

        console.log('signers', await elect.methods.getCurrentValidatorSigners().call())
      } catch (err) {
        console.log(err)
        await sleep(1000)
      }
    })

    it('slash for downtime', async function(this: any) {
      this.timeout(0) // Disable test timeout
      try {
        const slasher = await kit._web3Contracts.getDowntimeSlasher()
        const elect = await kit._web3Contracts.getElection()

        const blockNumber = await web3.eth.getBlockNumber()

        console.info('at block', blockNumber)

        await waitUntilBlock(blockNumber + 20)
        console.info('at block', await web3.eth.getBlockNumber())
        console.log('signers', await elect.methods.getCurrentValidatorSigners().call())

        doubleSigningBlock = await web3.eth.getBlock(blockNumber + 15)

        for (let i = blockNumber; i < blockNumber + 1; i++) {
          console.log('block', i, await slasher.methods.getParentSealBitmap(i).call())
        }

        const signer = await slasher.methods
          .validatorSignerAddressFromSet(4, blockNumber + 12)
          .call()

        const validator = (await kit.web3.eth.getAccounts())[0]
        await kit.web3.eth.personal.unlockAccount(validator, '', 1000000)
        console.log(validator)

        const lockedGold = await kit.contracts.getLockedGold()
        const accounts = await kit.contracts.getAccounts()

        console.log('signer to account', await accounts.signerToAccount(signer))

        console.log('incentives', await slasher.methods.slashingIncentives().call())

        console.log('total', (await lockedGold.getAccountTotalLockedGold(signer)).toString(10))
        console.log(
          'nonvoting',
          (await lockedGold.getAccountNonvotingLockedGold(signer)).toString(10)
        )

        console.log('locked balance', await web3.eth.getBalance(lockedGold.address))

        const valid = await kit._web3Contracts.getValidators()

        const history = await valid.methods.getHistory(signer).call()
        const historyIndex = history[0].length - 1
        console.log('history', history, historyIndex)

        console.log('registry', await slasher.methods.getSlasher().call(), slasher.options.address)

        console.log(
          'check',
          await slasher.methods.debugIsDown(signer, blockNumber + 12, 4, 4).call()
        )

        await slasher.methods
          .slash(
            signer,
            blockNumber + 12,
            4,
            4,
            historyIndex,
            [],
            [],
            [],
            [NULL_ADDRESS],
            [NULL_ADDRESS],
            [0]
          )
          .send({ from: validator, gas: 5000000 })

        console.log('remaining', (await lockedGold.getAccountTotalLockedGold(signer)).toString(10))
      } catch (err) {
        console.log(err)
        await sleep(1000)
      }
    })
  })

  describe('test slashing for double signing', () => {
    before(async function(this: any) {
      this.timeout(0) // Disable test timeout
      await restart()

      try {
        const block = await web3.eth.getBlock(123)
        // console.log('header', block)
        const blockRlp = rlp.encode(headerArray(web3, block))

        const downtimeSlasher = await kit._web3Contracts.getDowntimeSlasher()
        const elect = await kit._web3Contracts.getElection()

        console.log('signers', await elect.methods.getCurrentValidatorSigners().call())

        const hash = await downtimeSlasher.methods.hashHeader(blockRlp).call()
        console.info('hash', hash)

        const signer = await downtimeSlasher.methods.validatorSignerAddressFromSet(2, 100).call()
        console.info('signer', signer)

        console.info('at block', await web3.eth.getBlockNumber())

        const bitmap = await downtimeSlasher.methods
          .getVerifiedSealBitmapFromHeader(blockRlp)
          .call({ gas: 1000000 })
        console.info('bitmap', bitmap)
      } catch (err) {
        console.log(err)
        await sleep(1000)
      }
    })

    it('slash for double signing', async function(this: any) {
      this.timeout(0) // Disable test timeout
      try {
        const slasher = await kit._web3Contracts.getDoubleSigningSlasher()
        const elect = await kit._web3Contracts.getElection()

        await waitUntilBlock(doubleSigningBlock.number)
        console.info('at block', await web3.eth.getBlockNumber())
        console.log('signers', await elect.methods.getCurrentValidatorSigners().call())

        const other = rlp.encode(headerArray(web3, doubleSigningBlock))

        //console.log('at 245', (await web3.eth.getBlock(245)).raw)

        const num = await slasher.methods.getBlockNumberFromHeader(other).call()
        console.log('number', num)

        const header = rlp.encode(headerArray(web3, await web3.eth.getBlock(num)))

        const bitmap2 = await slasher.methods.getVerifiedSealBitmapFromHeader(other).call()
        const bitmap = await slasher.methods.getVerifiedSealBitmapFromHeader(header).call()
        const hash = await slasher.methods.hashHeader(header).call()
        console.log(header, bitmap, hash)

        let bmNum1 = new BigNumber(bitmap).toNumber()
        let bmNum2 = new BigNumber(bitmap2).toNumber()
        let signerIdx = 0
        for (let i = 0; i < 5; i++) {
          if ((bmNum1 & 1) === 1 && (bmNum2 & 1) === 1) break
          signerIdx++
          bmNum1 = bmNum1 >> 1
          bmNum2 = bmNum2 >> 1
        }
        console.log('index', signerIdx)

        const valid = await kit._web3Contracts.getValidators()

        const signer = await slasher.methods.validatorSignerAddressFromSet(signerIdx, num).call()
        const validator = (await kit.web3.eth.getAccounts())[0]
        await kit.web3.eth.personal.unlockAccount(validator, '', 1000000)
        console.log(validator)

        const lockedGold = await kit.contracts.getLockedGold()
        const accounts = await kit.contracts.getAccounts()

        console.log('signer to account', await accounts.signerToAccount(signer))

        console.log('incentives', await slasher.methods.slashingIncentives().call())

        console.log('total', (await lockedGold.getAccountTotalLockedGold(signer)).toString(10))
        console.log(
          'nonvoting',
          (await lockedGold.getAccountNonvotingLockedGold(signer)).toString(10)
        )

        console.log(
          'BN',
          await slasher.methods.checkForDoubleSigning(signer, signerIdx, header, other).call()
        )

        console.log('locked balance', await web3.eth.getBalance(lockedGold.address))

        const blockNumber = await web3.eth.getBlockNumber()
        const history = await valid.methods.getHistory(signer).call()
        const historyIndex = history[0].length - 1
        console.log('history', history, historyIndex)

        console.log(await valid.methods.debugCheck().call())
        console.log('registry', await slasher.methods.getSlasher().call(), slasher.options.address)

        try {
          console.log('epoch at', num, await slasher.methods.getEpochNumberOfBlock(num).call())
          console.log('epoch now', await slasher.methods.getEpochNumberOfBlock(blockNumber).call())

          console.log(
            'group 22',
            await valid.methods.groupMembershipInEpoch(signer, 22, historyIndex).call()
          )
          console.log(
            'group 23',
            await valid.methods.groupMembershipInEpoch(signer, 23, historyIndex).call()
          )
          console.log(
            'group 24',
            await valid.methods.groupMembershipInEpoch(signer, 24, historyIndex).call()
          )
          console.log(
            'group',
            await slasher.methods.groupMembershipAtBlock(signer, num, historyIndex).call()
          )
          console.log(
            'group now',
            await slasher.methods.groupMembershipAtBlock(signer, blockNumber, historyIndex).call()
          )
        } catch (err) {
          console.log(err)
        }

        await slasher.methods
          .slash(
            signer,
            signerIdx,
            header,
            other,
            historyIndex,
            [],
            [],
            [],
            [NULL_ADDRESS],
            [NULL_ADDRESS],
            [0]
          )
          .send({ from: validator, gas: 5000000 })

        console.log('remaining', (await lockedGold.getAccountTotalLockedGold(signer)).toString(10))
      } catch (err) {
        console.log(err)
        await sleep(1000)
      }
    })
  })
})

function headerArray(web3: Web3, block: any) {
  return [
    block.parentHash,
    block.sha3Uncles,
    block.miner,
    block.stateRoot,
    block.transactionsRoot,
    block.receiptsRoot,
    block.logsBloom,
    web3.utils.toHex(block.difficulty),
    block.number,
    block.gasLimit,
    block.gasUsed,
    block.timestamp,
    block.extraData,
    block.mixHash,
    block.nonce,
  ]
}

/*function istanbulExtraDataArray(ist: any) {
  return [
    ist.addedValidators,
    ist.addedValidatorsPublicKeys,
    ist.removedValidators,
    ist.seal,
    ist.aggregatedSeal,
    ist.parentAggregatedSeal,
    ist.epochData,
  ]
}*/
