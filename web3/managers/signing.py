import collections

import rlp

from web3.utils.address import to_address
from web3.utils.crypto import sha3
from web3.utils.encoding import (
    to_decimal,
    encode_hex,
    decode_hex,
)
from web3.utils.transactions import (
    is_bitcoin_available,
    Transaction,
    serialize_transaction,
    add_signature_to_transaction,
)

from .base import BaseManager
from .wrapper import ManagerWrapper


class BaseSendRawTransactionMixin(ManagerWrapper, BaseManager):
    _known_transactions = None
    _known_nonces = None

    def __init__(self, *args, **kwargs):
        # TODO: extract transaction nonce tracking into it's own *thing*
        self._known_transactions = collections.defaultdict(set)
        self._known_nonces = collections.defaultdict(set)
        super(BaseSendRawTransactionMixin, self).__init__(*args, **kwargs)

    def _get_nonces_and_cleanup(self, addr, chain_nonce):
        all_txns = {
            txn_hash: self.request_blocking(
                'eth_getTransactionByHash',
                [txn_hash],
            ) for txn_hash in self._known_transactions[addr]
        }
        for txn_hash, txn in all_txns.items():
            if txn is None:
                continue
            txn_nonce = to_decimal(txn['nonce'])
            if txn_nonce < chain_nonce:
                self._known_transactions[addr].discard(txn_hash)
            else:
                yield txn_nonce

        all_known_nonces = tuple(self._known_nonces[addr])
        for nonce in all_known_nonces:
            if nonce < chain_nonce:
                self._known_nonces[addr].discard(nonce)
            else:
                yield nonce

    def get_chain_nonce(self, addr):
        chain_nonce = to_decimal(self.request_blocking(
            'eth_getTransactionCount',
            [addr, 'pending']
        ))
        return chain_nonce

    def get_nonce(self, addr):
        chain_nonce = self.get_chain_nonce(addr)
        tracked_txn_nonces = tuple(self._get_nonces_and_cleanup(addr, chain_nonce))
        nonce = max(0, chain_nonce, *tracked_txn_nonces)
        if nonce == 0 and not tracked_txn_nonces:
            return -1
        else:
            return nonce

    def get_transaction_signature(self, serialized_txn):
        raise NotImplementedError("Must be implemented by subclasses")

    def sign_and_serialize_transaction(self, transaction):
        serialized_txn = serialize_transaction(transaction)
        signature = self.get_transaction_signature(transaction)
        signed_transaction = add_signature_to_transaction(
            serialized_txn,
            signature,
        )
        signed_and_serialized_txn = rlp.encode(signed_transaction, Transaction)
        return signed_and_serialized_txn

    def construct_full_transaction(self, base_transaction):
        txn_from = base_transaction['from']
        full_txn = dict(**base_transaction)
        full_txn.setdefault('nonce', self.get_nonce(txn_from) + 1)
        full_txn.setdefault('gasPrice', self.request_blocking(
            'eth_gasPrice', []
        ))
        full_txn.setdefault('gas', hex(90000))
        full_txn.setdefault('value', '0x0')
        full_txn.setdefault('to', '')
        full_txn.setdefault('data', '')
        return full_txn

    TXN_SENDING_METHODS = {
        'eth_sendTransaction',
        'eth_sendRawTransaction',
        'personal_signAndSendTransaction',
        'personal_sendTransaction',
    }

    def request_blocking(self, method, params):
        if method == 'eth_sendTransaction':
            base_transaction = params[0]
            # create a fully signed transaction and send through the
            # `eth_sendRawTransaction` endpoint instead.
            full_transaction = self.construct_full_transaction(base_transaction)
            raw_transaction_bytes = self.sign_and_serialize_transaction(
                full_transaction,
            )
            raw_transaction_bytes_as_hex = encode_hex(raw_transaction_bytes)
            return self.request_blocking(
                'eth_sendRawTransaction', [raw_transaction_bytes_as_hex],
            )

        result = super(BaseSendRawTransactionMixin, self).request_blocking(
            method, params,
        )
        if method in self.TXN_SENDING_METHODS:
            if method == 'eth_sendRawTransaction':
                txn = rlp.decode(decode_hex(params[0]), Transaction)
                self._known_transactions[to_address(txn.sender)].add(result)
                self._known_nonces[to_address(txn.sender)].add(txn.nonce)
            else:
                txn = params[0]
                self._known_transactions[to_address(txn['from'])].add(result)
                if 'nonce' in txn:
                    self._known_nonces[to_address(txn['from'])].add(
                        to_decimal(txn['nonce'])
                    )
        return result


class DelegatedSigningManager(BaseSendRawTransactionMixin):
    def __init__(self, *args, **kwargs):
        self.signing_manager = kwargs.pop('signing_manager')
        super(DelegatedSigningManager, self).__init__(*args, **kwargs)

    def get_chain_nonce(self, addr):
        signer_nonce = to_decimal(self.signing_manager.request_blocking(
            'eth_getTransactionCount',
            [addr, 'pending']
        ))
        wrapped_nonce = to_decimal(self.wrapped_manager.request_blocking(
            'eth_getTransactionCount',
            [addr, 'pending']
        ))
        return max(signer_nonce, wrapped_nonce)

    def get_transaction_signature(self, transaction):
        serialized_txn = serialize_transaction(transaction)
        hash_to_sign = self.signing_manager.request_blocking(
            'web3_sha3', [encode_hex(serialized_txn)],
        )
        signature_hex = self.signing_manager.request_blocking(
            'eth_sign',
            [
                transaction['from'],
                hash_to_sign,
            ],
        )
        signature = decode_hex(signature_hex)
        return signature


class PrivateKeySigningManager(BaseSendRawTransactionMixin):
    def __init__(self, *args, **kwargs):
        if not is_bitcoin_available():
            raise ImportError(
                "In order to use the `PrivateKeySigningManager` the "
                "`bitcoin` and `secp256k1` packages must be installed."
            )
        self.keys = kwargs.pop('keys', {})
        super(PrivateKeySigningManager, self).__init__(*args, **kwargs)

    def register_private_key(self, key):
        from bitcoin import privtopub
        address = to_address(sha3(privtopub(key)[1:])[-40:])
        self.keys[address] = key

    def sign_and_serialize_transaction(self, transaction):
        txn_from = to_address(transaction['from'])
        if txn_from not in self.keys:
            raise KeyError("No signing key registered for from address: {0}".format(txn_from))
        transaction = Transaction(
            nonce=to_decimal(transaction['nonce']),
            gasprice=to_decimal(transaction['gasPrice']),
            startgas=to_decimal(transaction['gas']),
            to=transaction['to'],
            value=to_decimal(transaction['value']),
            data=decode_hex(transaction['data']),
        )
        transaction.sign(self.keys[txn_from])
        assert to_address(transaction.sender) == txn_from
        return rlp.encode(transaction, Transaction)
