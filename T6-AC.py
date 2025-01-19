from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import random

class AC:
    def __init__(self):
        self.certificados = {}
        self.ca_certificate = None
        self.ca_private_key = None

    def issueSelfsignedCertificate(self, common_name="AC-Raiz", country="BR", state="SC", locality="Fln", organization="UFSC"):
        """
        Cria um certificado autoassinado com validade de 1 ano para a CA.

        Args:
            common_name (str): O nome comum (CN) do certificado.
            country (str): O pais do certificado. 
            state (str): O estado do certificado. 
            locality (str): A cidade ou endereco do certificado. 
            organization (str): O nome da CA. 

        Returns:
            tuple: O certificado X.509 autoassinado e sua chave privada.
        """
        self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        self.ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        return self.ca_certificate, self.ca_private_key


    def issueEndCertificate(self, public_key, common_name, country, state, locality, organization):
        """
        Emite um certificado final assinado pela CA com validade de 1 ano.

        Args:
            public_key (CryptoRSA.RsaKey): A chave publica do requerente do certificado.
            common_name (str): O nome comum (CN) do certificado.
            country (str): O pais do certificado. 
            state (str): O estado do certificado. 
            locality (str): A cidade ou endereco do certificado. 
            organization (str): O nome da organizacao requerente. 

        Returns:
            cert (Certificate): O certificado X.509.
        """
        if not self.ca_certificate or not self.ca_private_key:
            raise ValueError("A CA ainda não possui um certificado autoassinado.")

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(self.ca_private_key, hashes.SHA256())
        )
        self.certificados[common_name] = cert
        return cert

    def validateCertificate(self, cert):
        """
        Recupera a chave pública de um certificado se este não estiver expirado e tenha sido assinado por esta AC.
        Obs: a validacao feita neste metodo apenas se refere a data de validade do certificado e se este foi assinado pela AC, sendo assim, uma simplificação.

        Args:
            cert (Certificate): O certificado a ser validado.

        Returns:
            CryptoRSA.RsaKey or None: A chave publica do certificado, ou None se o certificado não for valido.
        """
        if datetime.utcnow() < cert.not_valid_before or datetime.utcnow() > cert.not_valid_after:
            return None
        try:
            self.ca_certificate.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return cert.public_key()
        except Exception as e:
            print(f"Erro ao validar o certificado: {e}")
            return None
