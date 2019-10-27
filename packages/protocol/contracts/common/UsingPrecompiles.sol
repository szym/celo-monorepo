pragma solidity ^0.5.3;

import "./FixidityLib.sol";

contract UsingPrecompiles {
  using FixidityLib for FixidityLib.Fraction;

  /**
   * @notice calculate a * b^e for fractions a, b, e to `decimals` precision
   * @param decimals precision
   * @return numerator/denominator of the computed quantity (not reduced).
   */
  function fractionMulExp(
    FixidityLib.Fraction memory a,
    FixidityLib.Fraction memory b,
    FixidityLib.Fraction memory e,
    uint256 decimals
  )
    internal
    view
    returns (FixidityLib.Fraction memory)
  {
    uint256 aValue = a.unwrap();
    uint256 bValue = b.unwrap();
    uint256 eValue = e.unwrap();

    uint256 returnNumerator;
    uint256 returnDenominator;
    // solhint-disable-next-line no-inline-assembly
    assembly {
      let newCallDataPosition := mload(0x40)
      mstore(0x40, add(newCallDataPosition, calldatasize))
      mstore(newCallDataPosition, aValue)
      mstore(add(newCallDataPosition, 32), bValue)
      mstore(add(newCallDataPosition, 64), eValue)
      mstore(add(newCallDataPosition, 96), decimals)
      let delegatecallSuccess := staticcall(
        1050,                 // estimated gas cost for this function
        0xfc,
        newCallDataPosition,
        0x80,                 // input size, 4 * 32 = 128 bytes
        0,
        0
      )

      let returnDataSize := returndatasize
      let returnDataPosition := mload(0x40)
      mstore(0x40, add(returnDataPosition, returnDataSize))
      returndatacopy(returnDataPosition, 0, returnDataSize)

      switch delegatecallSuccess
      case 0 {
        revert(returnDataPosition, returnDataSize)
      }
      default {
        returnNumerator := mload(returnDataPosition)
        returnDenominator := mload(add(returnDataPosition, 32))
      }
    }
    
    return FixidityLib.newFixedFraction(returnNumerator, returnDenominator);
  }

  /**
   * @notice Returns the current epoch size in blocks.
   * @return The current epoch size in blocks.
   */
  function getEpochSize() public view returns (uint256) {
    uint256 ret;
    // solhint-disable-next-line no-inline-assembly
    assembly {
      let newCallDataPosition := mload(0x40)
      let success := staticcall(1000, 0xf8, newCallDataPosition, 0, 0, 0)

      returndatacopy(add(newCallDataPosition, 32), 0, 32)
      ret := mload(add(newCallDataPosition, 32))
    }
    return ret;
  }

  function getEpochNumber() public view returns (uint256) {
    uint256 epochSize = getEpochSize();
    uint256 epochNumber = block.number / epochSize;
    if (block.number % epochSize == 0) {
      epochNumber = epochNumber - 1;
    }
    return epochNumber;
  }

  /**
   * @notice Gets a validator address from the current validator set.
   * @param index Index of requested validator in the validator set as sorted by the election.
   * @return Address of validator at the requested index.
   */
  function validatorAddressFromCurrentSet(uint256 index) public view returns (address) {
    address validatorAddress;
    assembly {
      let newCallDataPosition := mload(0x40)
      mstore(newCallDataPosition, index)
      let success := staticcall(5000, 0xfa, newCallDataPosition, 32, 0, 0)
      returndatacopy(add(newCallDataPosition, 64), 0, 32)
      validatorAddress := mload(add(newCallDataPosition, 64))
    }

    return validatorAddress;
  }

  /**
   * @notice Gets the size of the current elected validator set.
   * @return Size of the current elected validator set.
   */
  function numberValidatorsInCurrentSet() public view returns (uint256) {
    uint256 numberValidators;
    assembly {
      let success := staticcall(5000, 0xf9, 0, 0, 0, 0)
      let returnData := mload(0x40)
      returndatacopy(returnData, 0, 32)
      numberValidators := mload(returnData)
    }

    return numberValidators;
  }
}
