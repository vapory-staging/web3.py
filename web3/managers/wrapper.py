class ManagerWrapper(object):
    def __init__(self, wrapped_manager):
        self.wrapped_manager = wrapped_manager

    @property
    def provider(self):
        return self.wrapped_manager.provider

    @property
    def pending_requests(self):
        return self.wrapped_manager.pending_requests

    def setProvider(self, provider):
        self.wrapped_manager.provider = provider

    def request_blocking(self, *args, **kwargs):
        return self.wrapped_manager.request_blocking(*args, **kwargs)

    def request_async(self, *args, **kwargs):
        return self.wrapped_manager.request_async(*args, **kwargs)

    def receive_blocking(self, *args, **kwargs):
        return self.wrapped_manager.receive_blocking(*args, **kwargs)

    def receive_async(self, *args, **kwargs):
        return self.wrapped_manager.receive_async(*args, **kwargs)
