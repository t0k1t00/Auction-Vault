from cryptography.fernet import Fernet
from src.config import get_settings

settings = get_settings()

cipher = Fernet(settings.encryption_key.encode())


def encrypt_data(data: str) -> str:
    return cipher.encrypt(data.encode()).decode()


def decrypt_data(data: str) -> str:
    return cipher.decrypt(data.encode()).decode()
