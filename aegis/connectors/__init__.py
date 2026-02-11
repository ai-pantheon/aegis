"""
Chain connectors for the Seal Authority network.
Each connector implements communication with one blockchain type.
"""

from aegis.connectors.base import ChainConnector
from aegis.connectors.ethereum import EthereumConnector
from aegis.connectors.self_hosted import SelfHostedConnector
from aegis.connectors.bitcoin import BitcoinConnector
from aegis.connectors.arweave import ArweaveConnector
from aegis.connectors.solana import SolanaConnector
from aegis.connectors.filecoin import FilecoinConnector

__all__ = [
    "ChainConnector",
    "EthereumConnector",
    "SelfHostedConnector",
    "BitcoinConnector",
    "ArweaveConnector",
    "SolanaConnector",
    "FilecoinConnector",
]
