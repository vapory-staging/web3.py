import warnings

from web3.managers import (  # noqa: F401
    RequestManager,
    ManagerWrapper,
    BaseSendRawTransactionMixin,
    DelegatedSigningManager,
    PrivateKeySigningManager,
)


warnings.warn(DeprecationWarning(
    "The `web3.providers.manager` module has moved to `web3.managers`.  Please "
    "update your code to reflect this new code path as the "
    "`web3.providers.manager` module will be removed in a future release"
))
