class BaseManager(object):
    provider = None

    def __init__(self, provider):
        self.provider = provider

    def setProvider(self, provider):
        self.provider = provider

    def request_blocking(self, method, params):
        """
        Make a synchronous request to the provider
        """
        raise NotImplementedError("Must be implemented by subclasses")

    def request_async(self, method, params):
        """
        Make an asyncronous request to the provider
        """
        raise NotImplementedError("Must be implemented by subclasses")

    def receive_blocking(self, request_id, timeout=None):
        """
        Retrieve the response for the given request_id.  Blocks until response
        is received or timout seconds have elapsed.
        """
        raise NotImplementedError("Must be implemented by subclasses")

    def receive_async(self, request_id, callback):
        """
        Enqueus `callback` to be called with the response for the given
        request_id.  Returns immediately.
        """
        raise NotImplementedError("Callback pattern not implemented")
