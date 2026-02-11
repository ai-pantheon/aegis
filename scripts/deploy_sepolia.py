"""
Deploy SealAuthority.sol to Ethereum Sepolia testnet.

Usage:
    # Set environment variables first:
    export SEPOLIA_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
    export DEPLOYER_PRIVATE_KEY="0x..."
    export SIGNER_ADDRESS="0x..."  # The Cloak signer to authorize

    python scripts/deploy_sepolia.py

This deploys one SealAuthority instance (share index 1, threshold 4, total 7).
After deployment, it stores an encrypted share and authorizes the signer.
"""

import json
import os
import sys
import time
from pathlib import Path

from solcx import compile_source, install_solc
from web3 import Web3
from web3.middleware import ExtraDataToPoa


def compile_contract():
    """Compile SealAuthority.sol and return ABI + bytecode."""
    sol_path = Path(__file__).parent.parent / "contracts" / "SealAuthority.sol"
    source = sol_path.read_text()

    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version="0.8.24",
    )

    # Key format: <filename>:<ContractName>
    contract_key = "<stdin>:SealAuthority"
    contract_data = compiled[contract_key]

    return contract_data["abi"], contract_data["bin"]


def deploy(w3, account, abi, bytecode, share_index=1, threshold=4, total_shares=7):
    """Deploy the SealAuthority contract."""
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    # Build constructor transaction
    tx = contract.constructor(share_index, threshold, total_shares).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })

    # Estimate gas and add 20% buffer
    gas_estimate = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)

    # Sign and send
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  Deploy tx sent: {tx_hash.hex()}")

    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    return receipt


def store_share(w3, account, contract, encrypted_share: bytes):
    """Store the encrypted Shamir share in the contract."""
    tx = contract.functions.setShare(encrypted_share).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    gas_estimate = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    return receipt


def add_signer(w3, account, contract, signer_address: str):
    """Authorize a Cloak signer address."""
    tx = contract.functions.addSigner(
        Web3.to_checksum_address(signer_address)
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    gas_estimate = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    return receipt


def main():
    # ── Config ──
    rpc_url = os.environ.get("SEPOLIA_RPC_URL")
    private_key = os.environ.get("DEPLOYER_PRIVATE_KEY")
    signer_address = os.environ.get("SIGNER_ADDRESS")

    if not rpc_url:
        print("ERROR: Set SEPOLIA_RPC_URL environment variable")
        print("  Get one free at https://www.alchemy.com/ or https://infura.io/")
        sys.exit(1)

    if not private_key:
        print("ERROR: Set DEPLOYER_PRIVATE_KEY environment variable")
        print("  This is the wallet that will own the contract")
        sys.exit(1)

    # ── Connect ──
    print(f"Connecting to Sepolia...")
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    # Add PoA middleware for Sepolia
    w3.middleware_onion.inject(ExtraDataToPoa, layer=0)

    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    print(f"  Connected. Chain ID: {chain_id}")
    if chain_id != 11155111:
        print(f"  WARNING: Expected Sepolia (11155111), got {chain_id}")

    # ── Account ──
    account = w3.eth.account.from_key(private_key)
    balance = w3.eth.get_balance(account.address)
    balance_eth = w3.from_wei(balance, "ether")
    print(f"  Deployer: {account.address}")
    print(f"  Balance: {balance_eth} ETH")

    if balance == 0:
        print("\nERROR: No Sepolia ETH. Get some from:")
        print("  https://sepoliafaucet.com/")
        print("  https://faucet.sepolia.dev/")
        print("  https://www.alchemy.com/faucets/ethereum-sepolia")
        sys.exit(1)

    # ── Compile ──
    print("\nCompiling SealAuthority.sol...")
    abi, bytecode = compile_contract()
    print(f"  Compiled. Bytecode: {len(bytecode)} chars")

    # ── Deploy ──
    print("\nDeploying SealAuthority (share 1, threshold 4, total 7)...")
    receipt = deploy(w3, account, abi, bytecode)

    contract_address = receipt.contractAddress
    status = "SUCCESS" if receipt.status == 1 else "FAILED"
    gas_used = receipt.gasUsed
    print(f"  Status: {status}")
    print(f"  Contract: {contract_address}")
    print(f"  Gas used: {gas_used}")
    print(f"  Block: {receipt.blockNumber}")
    print(f"  Etherscan: https://sepolia.etherscan.io/address/{contract_address}")

    if receipt.status != 1:
        print("Deployment failed!")
        sys.exit(1)

    # ── Interact ──
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Verify deployment
    info = contract.functions.info().call()
    print(f"\n  On-chain info: shareIndex={info[0]}, threshold={info[1]}, "
          f"totalShares={info[2]}, active={info[3]}, hasShare={info[4]}")

    # Store a test share (encrypted placeholder — real share goes here in production)
    print("\nStoring test encrypted share...")
    test_share = os.urandom(64)  # Placeholder — real share is Shamir output
    receipt2 = store_share(w3, account, contract, test_share)
    print(f"  Status: {'SUCCESS' if receipt2.status == 1 else 'FAILED'}")
    print(f"  Gas used: {receipt2.gasUsed}")

    # Add signer if provided
    if signer_address:
        print(f"\nAuthorizing signer: {signer_address}")
        receipt3 = add_signer(w3, account, contract, signer_address)
        print(f"  Status: {'SUCCESS' if receipt3.status == 1 else 'FAILED'}")
        print(f"  Gas used: {receipt3.gasUsed}")

    # ── Save deployment info ──
    deployment_info = {
        "network": "sepolia",
        "chain_id": chain_id,
        "contract_address": contract_address,
        "deployer": account.address,
        "share_index": 1,
        "threshold": 4,
        "total_shares": 7,
        "block_number": receipt.blockNumber,
        "tx_hash": receipt.transactionHash.hex(),
        "gas_used": gas_used,
        "deployed_at": int(time.time()),
        "etherscan_url": f"https://sepolia.etherscan.io/address/{contract_address}",
    }

    deploy_dir = Path(__file__).parent.parent / "deployments"
    deploy_dir.mkdir(exist_ok=True)
    deploy_file = deploy_dir / "sepolia-ethereum.json"
    deploy_file.write_text(json.dumps(deployment_info, indent=2))
    print(f"\nDeployment info saved to: {deploy_file}")

    # Save ABI for frontend/integration use
    abi_file = deploy_dir / "SealAuthority.abi.json"
    abi_file.write_text(json.dumps(abi, indent=2))
    print(f"ABI saved to: {abi_file}")

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT COMPLETE")
    print(f"  Contract: {contract_address}")
    print(f"  Network:  Sepolia (Chain ID {chain_id})")
    print(f"  Explorer: https://sepolia.etherscan.io/address/{contract_address}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
