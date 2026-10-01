"""
Optional: anchors the latest audit entry_hash to the AuditAnchor contract.

Needs "pip install web3" and env vars WEB3_RPC_URL, ANCHOR_CONTRACT_ADDRESS,
ANCHOR_PRIVATE_KEY. If any is missing this is a safe no-op.
"""
import os

ANCHOR_ABI = [{
    "inputs": [{"internalType": "bytes32", "name": "entryHash", "type": "bytes32"}],
    "name": "anchor",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function",
}]


def anchor_hash(entry_hash: str) -> dict:
    rpc_url = os.environ.get("WEB3_RPC_URL")
    address = os.environ.get("ANCHOR_CONTRACT_ADDRESS")
    private_key = os.environ.get("ANCHOR_PRIVATE_KEY")

    if not (rpc_url and address and private_key):
        print("[AUDIT] blockchain anchoring not configured")
        return {"anchored": False, "reason": "not configured"}
    try:
        from web3 import Web3
    except ImportError:
        print("[AUDIT] blockchain anchoring not configured (web3 not installed)")
        return {"anchored": False, "reason": "web3 not installed"}

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        account = w3.eth.account.from_key(private_key)
        contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ANCHOR_ABI)
        tx = contract.functions.anchor(bytes.fromhex(entry_hash)).build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
        })
        signed = account.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw)
        print(f"[AUDIT] Anchored {entry_hash[:16]}... in tx {tx_hash.hex()}")
        return {"anchored": True, "tx_hash": tx_hash.hex()}
    except Exception as e:
        print(f"[AUDIT] blockchain anchoring failed: {e}")
        return {"anchored": False, "reason": str(e)}
