// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

contract EthereumDIDRegistry {
  function validDelegate(address identity, bytes32 delegateType, address delegate) public pure returns(bool) {
      return delegateType == 'veriKey' && identity == delegate;
  }
}

contract AbstractClaimsVerifier {
  struct EIP712Domain {
    string  name;
    string  version;
    uint256 chainId;
    address verifyingContract;
  }

  bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  );

  bytes32 DOMAIN_SEPARATOR;

  constructor (
    string memory name, 
    string memory version, 
    uint256 chainId, 
    address verifyingContract) public {
    DOMAIN_SEPARATOR = hash(
      EIP712Domain({
        name: name,
        version: version,
        chainId: chainId,
        verifyingContract: verifyingContract
    }));
  }

  function hash(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        EIP712DOMAIN_TYPEHASH,
        keccak256(bytes(eip712Domain.name)),
        keccak256(bytes(eip712Domain.version)),
        eip712Domain.chainId,
        eip712Domain.verifyingContract
    ));
  }
}

struct Claim {
    address issuer;
	address subject;
	uint256 validFrom;
	uint256 validTo;
}

contract RevocationRegistry {
  mapping (bytes32 => mapping (address => uint)) public revocations;

  function revoke(bytes32 digest) public returns (bool) {
    revocations[digest][msg.sender] = block.number;
    return true;
  }

  function revoked(address party, bytes32 digest) public view returns (bool) {
    return revocations[digest][party] > 0;
  }
}

contract MembershipClaimsVerifier is AbstractClaimsVerifier {

  constructor (address _did, address _revocations) 
    AbstractClaimsVerifier(
      "1729MembershipClaims",
      "1",
      1,
      address(this)
    ) public {
        didRegistry = EthereumDIDRegistry(_did);
        revocationRegistry = RevocationRegistry(_revocations);
    }

  EthereumDIDRegistry didRegistry;
  RevocationRegistry revocationRegistry;

  function verify(Claim memory claim, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
    bytes32 digest = keccak256(
      abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR,
        hash(claim)
      )
    );
    address issuer = ecrecover(digest, v, r, s);
    require(issuer != address(0));
    
    return true;
  }
  
  function hash(Claim memory claim) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(claim.issuer, claim.subject, claim.validFrom, claim.validTo));
  }

}

struct Signature {
  uint8 v;
  bytes32 r;
  bytes32 s;
}

contract MembershipClaimsRegistry {
  MembershipClaimsVerifier verifier;
  
  mapping(address => mapping(bytes32 => Signature)) signatures;

  constructor(address _verifier) public {
    verifier = MembershipClaimsVerifier(_verifier);
  }
  
  function addClaim(Claim memory claim, uint8 v, bytes32 r, bytes32 s) public {
    require(verifier.verify(claim, v, r, s), "claim not initially valid");
    signatures[claim.issuer][verifier.hash(claim)] = Signature(v, r, s);
  }
  
  function checkClaim(Claim memory claim) public view returns (bool) {
    Signature memory signature = signatures[claim.issuer][verifier.hash(claim)];
    return verifier.verify(claim, signature.v, signature.r, signature.s);
  }
}
