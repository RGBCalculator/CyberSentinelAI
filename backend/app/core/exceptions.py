class CyberSentinelException(Exception):
    """Base class for custom application exceptions."""
    def __init__(self, detail: str = "An error occurred"):
        self.detail = detail
        super().__init__(self.detail)

class InvalidCredentialsException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "Invalid authentication credentials provided.")

class UserAlreadyExistsException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "A user with this email or username already exists.")

class EmailAlreadyExistsException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "This email address is already in use.")

class AccountLockedException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "Account has been temporarily locked due to multiple failed login attempts.")

class InactiveAccountException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "Account is currently inactive. Please contact support.")

class DeletedAccountException(CyberSentinelException):
    def __init__(self, detail: str = None):
        super().__init__(detail or "Account has been deleted.")
