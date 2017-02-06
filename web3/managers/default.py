import uuid
import json

from web3.utils.compat import (
    spawn,
)
from web3.utils.string import force_text
from web3.utils.types import (
    is_string,
    is_object,
)

from .base import BaseManager


class RequestManager(BaseManager):
    _pending_requests = None

    def setProvider(self, provider):
        self.provider = provider

    @property
    def pending_requests(self):
        if self._pending_requests is None:
            self._pending_requests = {}
        return self._pending_requests

    def request_blocking(self, method, params):
        """
        Make a synchronous request using the provider
        """
        response_raw = self.provider.make_request(method, params)

        if is_string(response_raw):
            response = json.loads(force_text(response_raw))
        elif is_object(response_raw):
            response = response_raw

        if "error" in response:
            raise ValueError(response["error"])

        return response['result']

    def request_async(self, method, params):
        # TODO: put these in a queue so they can be cancelled.
        request_id = uuid.uuid4()
        self.pending_requests[request_id] = spawn(
            self.request_blocking,
            method,
            params,
        )
        return request_id

    def receive_blocking(self, request_id, timeout=None):
        try:
            request = self.pending_requests.pop(request_id)
        except KeyError:
            raise KeyError("Request for id:{0} not found".format(request_id))
        else:
            response_raw = request.get(timeout=timeout)

        response = json.loads(response_raw)

        if "error" in response:
            raise ValueError(response["error"])

        return response['result']

    def receive_async(self, request_id, *args, **kwargs):
        raise NotImplementedError("Callback pattern not implemented")
