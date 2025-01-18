from Cryptodome.PublicKey import RSA as CryptoRSA
from Cryptodome.PublicKey import DSA as CryptoDSA
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Hash import SHA256
from base64 import b64encode, b64decode

class RSA:
    def __init__(self, key_size: int = 2048, public_exponent: int = 65537):
        """
        Inicializa a classe RSA gerando um par de chaves RSA com o tamanho e o expoente público especificados.

        :param key_size: Tamanho da chave RSA em bits (padrão 2048).
        :param public_exponent: Expoente público para a chave RSA (padrão 65537).
        """
        self.private_key: CryptoRSA.RsaKey
        self.public_key: CryptoRSA.RsaKey
        self.generate_keys(key_size, public_exponent)

    def generate_keys(self, key_size: int, public_exponent: int):
        """
        Gera um par de chaves RSA e armazena a chave privada e pública na instância.

        :param key_size: Tamanho da chave RSA em bits.
        :param public_exponent: Expoente público da chave RSA.
        """
        key = CryptoRSA.generate(key_size, e=public_exponent)
        self.private_key = key
        self.public_key = key.public_key()

    def sign_message(self, message: str) -> str:
        """
        Assina digitalmente uma mensagem usando a chave privada RSA.

        :param message: A mensagem em texto simples a ser assinada.
        :return: Assinatura da mensagem codificada em base64.
        """
        message_bytes = message.encode('utf-8')
        hash = SHA256.new(message_bytes)
        signature = pkcs1_15.new(self.private_key).sign(hash)
        return b64encode(signature).decode('utf-8')
        

    def verify_signature(self, message: str, signature: str, public_key: CryptoRSA.RsaKey) -> bool:
        """
        Verifica uma assinatura RSA de uma mensagem usando a chave pública RSA.

        :param message: A mensagem original em texto simples.
        :param signature: A assinatura codificada em base64 a ser verificada.
        :param public_key: A chave pública RSA do remetente.
        :return: True se a assinatura for válida, False caso contrário.
        """
        try:
            message_bytes = message.encode('utf-8')
            hash = SHA256.new(message_bytes)
            signature_bytes = b64decode(signature)
            pkcs1_15.new(public_key).verify(hash, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False

class DSA:
    def __init__(self, key_size: int = 2048):
        """
        Inicializa a classe DSA gerando um par de chaves DSA com o tamanho especificado.

        :param key_size: Tamanho da chave DSA em bits (padrão 2048).
        """
        self.private_key: CryptoDSA
        self.public_key: CryptoDSA
        self.generate_keys(key_size)

    def generate_keys(self, key_size: int):
        """
        Gera um par de chaves DSA e armazena a chave privada e pública na instância.

        :param key_size: Tamanho da chave DSA em bits.
        """
        key = CryptoDSA.generate(key_size)
        self.private_key = key
        self.public_key = key.public_key()

    def sign_message(self, message: str) -> str:
        """
        Assina digitalmente uma mensagem usando a chave privada DSA.

        :param message: A mensagem em texto simples a ser assinada.
        :return: Assinatura da mensagem codificada em base64.
        """
        message_bytes = message.encode('utf-8')
        hash = SHA256.new(message_bytes)
        signature = DSS.new(self.private_key, 'fips-186-3').sign(hash)
        return b64encode(signature).decode('utf-8')

    def verify_signature(self, message: str, signature: str, public_key: CryptoDSA) -> bool:
        """
        Verifica uma assinatura DSA de uma mensagem usando a chave pública DSA.

        :param message: A mensagem original em texto simples.
        :param signature: A assinatura codificada em base64 a ser verificada.
        :param public_key: A chave pública DSA do remetente.
        :return: True se a assinatura for válida, False caso contrário.
        """
        try:
            message_bytes = message.encode('utf-8')
            hash = SHA256.new(message_bytes)
            signature_bytes = b64decode(signature)
            DSS.new(public_key, 'fips-186-3').verify(hash, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False
        
class ECDSA:
    def __init__(self, curve: str = 'P-256'):
        """
        Inicializa a classe ECDSA gerando um par de chaves ECDSA com a curva especificada.

        :param curve: Nome da curva elíptica (padrão 'P-256').
        """
        self.private_key: ECC.EccKey
        self.public_key: ECC.EccKey
        self.generate_keys(curve)

    def generate_keys(self, curve: str):
        """
        Gera um par de chaves ECDSA e armazena a chave privada e pública na instância.

        :param curve: Nome da curva elíptica para geração da chave.
        """
        key = ECC.generate(curve=curve)
        self.private_key = key
        self.public_key = key.public_key()
        

    def sign_message(self, message: str) -> str:
        """
        Assina digitalmente uma mensagem usando a chave privada ECDSA.

        :param message: A mensagem em texto simples a ser assinada.
        :return: Assinatura da mensagem codificada em base64.
        """
        message_bytes = message.encode('utf-8')
        hash = SHA256.new(message_bytes)
        signature = DSS.new(self.private_key, 'fips-186-3').sign(hash)
        return b64encode(signature).decode('utf-8')

    def verify_signature(self, message: str, signature: str, public_key: ECC.EccKey) -> bool:
        """
        Verifica uma assinatura ECDSA de uma mensagem usando a chave pública ECDSA.

        :param message: A mensagem original em texto simples.
        :param signature: A assinatura codificada em base64 a ser verificada.
        :param public_key: A chave pública ECDSA do remetente.
        :return: True se a assinatura for válida, False caso contrário.
        """
        try:
            message_bytes = message.encode('utf-8')
            hash = SHA256.new(message_bytes)
            signature_bytes = b64decode(signature)
            DSS.new(public_key, 'fips-186-3').verify(hash, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False
