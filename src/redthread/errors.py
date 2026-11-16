class RedthreadError(Exception):
    """Base class for errors we expect to surface to a user."""


class ConfigError(RedthreadError):
    pass


class ScopeError(RedthreadError):
    pass


class BudgetExceeded(RedthreadError):
    pass


class RunStopped(RedthreadError):
    pass


class RequestFailed(RedthreadError):
    pass


class LlmError(RedthreadError):
    pass


class BenchmarkError(RedthreadError):
    pass
