"""
Blockchain anchor: checks OUR glue code with a faked web3 module (no chain, no network).
This does not prove the contract is deployed or that a real transaction confirms — see README.
"""
import sys
import types
from unittest.mock import MagicMock

import pytest

from lambdas.audit_logger.blockchain_anchor import anchor_hash

ENTRY_HASH = "ab" * 32  # 64 hex chars = bytes32


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("WEB3_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("ANCHOR_CONTRACT_ADDRESS", "0x" + "11" * 20)
    monkeypatch.setenv("ANCHOR_PRIVATE_KEY", "0x" + "22" * 32)


@pytest.fixture
def fake_web3(monkeypatch):
    web3_class = MagicMock(name="Web3")
    w3 = web3_class.return_value
    w3.eth.account.from_key.return_value.address = "0xSender"
    w3.eth.get_transaction_count.return_value = 7
    w3.eth.send_raw_transaction.return_value = bytes.fromhex("33" * 32)
    account = w3.eth.account.from_key.return_value
    account.sign_transaction.return_value.raw_transaction = b"signed-bytes"

    module = types.ModuleType("web3")
    module.Web3 = web3_class
    monkeypatch.setitem(sys.modules, "web3", module)
    return web3_class, w3


def test_anchors_hash_as_bytes32_and_sends_signed_transaction(configured, fake_web3):
    web3_class, w3 = fake_web3
    result = anchor_hash(ENTRY_HASH)

    anchor_fn = w3.eth.contract.return_value.functions.anchor
    (arg,), _ = anchor_fn.call_args
    assert arg == bytes.fromhex(ENTRY_HASH) and len(arg) == 32
    w3.eth.send_raw_transaction.assert_called_once_with(b"signed-bytes")
    assert result == {"anchored": True, "tx_hash": "33" * 32}


def test_chain_errors_return_failure_instead_of_crashing(configured, fake_web3):
    _, w3 = fake_web3
    w3.eth.send_raw_transaction.side_effect = ConnectionError("rpc down")
    result = anchor_hash(ENTRY_HASH)
    assert result["anchored"] is False and "rpc down" in result["reason"]


def test_missing_web3_package_is_a_safe_noop(configured, monkeypatch):
    monkeypatch.setitem(sys.modules, "web3", None)  # makes "from web3 import Web3" raise ImportError
    assert anchor_hash(ENTRY_HASH) == {"anchored": False, "reason": "web3 not installed"}
