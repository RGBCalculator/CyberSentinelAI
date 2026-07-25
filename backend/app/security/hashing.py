import bcrypt

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt.
    
    Automatically generates a cryptographically secure salt.
    Returns the hashed password as a UTF-8 string.
    """
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_bytes.decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    """
    Verifies a plaintext password against a stored bcrypt hash.
    
    Uses bcrypt.checkpw which performs constant-time verification 
    to mitigate timing attacks.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
