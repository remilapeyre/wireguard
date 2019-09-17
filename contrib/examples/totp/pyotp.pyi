from typing import Optional, Union, List

import random

class TOTP:
    def __init__(self, s: str) -> None: ...
    def verify(self, otp: str) -> bool: ...
    def provisioning_uri(self, name: str, issuer_name: str = None) -> str: ...

def random_base32(length: int=16, random: random.SystemRandom = None, chars: List[str] = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')) -> str: ...
