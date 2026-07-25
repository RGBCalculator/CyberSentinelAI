class CyberSentinelException(Exception):
    """Base class for custom application exceptions."""
    pass

class InvalidCredentialsException(CyberSentinelException):
    pass

class UserAlreadyExistsException(CyberSentinelException):
    pass

class EmailAlreadyExistsException(CyberSentinelException):
    pass

class AccountLockedException(CyberSentinelException):
    pass

class InactiveAccountException(CyberSentinelException):
    pass

class DeletedAccountException(CyberSentinelException):
    pass
