from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.BestAvailableEncryption(b'22052001')
)

print(pem)

# print(key_array[0])
# print(key_array[1])
# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Shop_simulator"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Shop_simulator.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName(u"Shop_simulator.com"),
        x509.DNSName(u"www.Shop_simulator.com"),
        x509.DNSName(u"subdomain.Shop_simulator.com"),
    ]),
    critical=False,
# Sign the CSR with our private key.
# key es la clave privada de la aplicacion
).sign(private_key, hashes.SHA256())
# Write our CSR out to disk.
with open("../certificate_data/csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))





