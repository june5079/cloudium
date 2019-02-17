import OpenSSL, M2Crypto
import ssl, socket


for x in range (1,255):
        try:
                cert = ssl.get_server_certificate(('52.239.218.{}'.format(x), 443))
                x509 = M2Crypto.X509.load_cert_string(cert)
                print(x509.get_subject().as_text().split("CN=")[1])
        except:
                pass
