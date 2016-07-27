import pytest

from web3.providers.rpc import TestRPCProvider


def test_eth_getWork(web3):
    if isinstance(web3.currentProvider, TestRPCProvider):
        pytest.skip("The testrpc server doesn't implement `eth_estimateGas`")

    work = web3.eth.getWork()

    # TODO: this test could be better.
    assert work
