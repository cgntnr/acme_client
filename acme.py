import argparse
from logging import critical, shutdown
from types import resolve_bases
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
import requests
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import json
from hashlib import sha256
from dns_server import ACME_DNS_Server
import time
from cryptography import x509
from cert_https_server import Cert_Https_Server

from challenge_http_server import Challenge_Http_Server
from cryptography.hazmat.backends import default_backend

from shutdown_http_server import Shutdown_Server


class ACME_Client:



    def __init__(self, acme_server_url, domains, record_address):
        self.record_address = record_address
        self.private_rsa_key = generate_rsa_private_key()
        self.public_rsa_key = self.private_rsa_key.public_key()
        self.acme_server_url = acme_server_url
        self.domains = domains
        self.get_directory()
        self.get_nonce()

        self.private_rsa_key_cert = generate_rsa_private_key()
        with open('pk.pem', "wb") as f:
            f.write(self.private_rsa_key_cert.private_bytes(
                encoding=Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
    def get_directory(self):
        resp = requests.get(url=self.acme_server_url, verify="pebble.minica.pem")
        dir_json = resp.json()
        self.new_nonce_url = dir_json['newNonce']
        self.new_account_url = dir_json['newAccount']
        self.new_order_url = dir_json['newOrder']
        self.revoke_cert_url = dir_json['revokeCert'] 
        self.key_change_url = dir_json['keyChange'] 
        self.kid = None

    def get_nonce(self):
        resp = requests.head(self.new_nonce_url, verify="pebble.minica.pem")
        self.new_nonce = resp.headers['Replay-Nonce']

    def create_account(self):
        payload = {
            "termsOfServiceAgreed": True
        }
        response = self.acme_request(self.new_account_url, payload, False)
        self.kid = response.headers['Location']
        self.account_key = response.json()['key']

    def submit_order(self, domains):
        identifiers = []
        for domain in domains:
            identifiers.append({"type": "dns", "value": domain})
        payload = {"identifiers" : identifiers}
        response = self.acme_request(url=self.new_order_url, payload=payload, kid_known=True)
        self.order_url = response.headers['Location']
        resp_dict = response.json()    
        self.authorization_urls = resp_dict['authorizations'] # for when the order is pending
        self.finalize_url = resp_dict['finalize']

    ### post-as-get order's authorization urls ###
    def fetch_challenges(self, requested_challenge_type):
        self.challenges = []
        for url in self.authorization_urls:
            resp_dict = self.acme_request(url, "", True).json() #True as self.kid should be known at this point
            if requested_challenge_type == "http01":
                for challenge in resp_dict['challenges']:
                    if challenge['type'] == "http-01":
                        challenge['authorization_url'] = url
                        challenge['domain'] = resp_dict['identifier']['value']
                        self.challenges.append(challenge)
            else: ##case for dns01 challenges
                for challenge in resp_dict['challenges']:
                    if challenge['type'] == "dns-01":
                        challenge['authorization_url'] = url
                        challenge['domain'] = resp_dict['identifier']['value']
                        self.challenges.append(challenge)

    def handle_http01_challenge(self):
        for challenge in self.challenges:
            token_challenge = challenge['token']
            url_challenge = challenge['url']

            jwk_thumbprint = get_jwk_thumbprint(self)
            key_authorization = challenge['token'] + "." + jwk_thumbprint
            zone = challenge['domain'] + ". 60 A " + self.record_address
            self.dns_server = ACME_DNS_Server(zone, address=self.record_address, port=10053)
            self.dns_server.start()

            challenge_http_server = Challenge_Http_Server(host=self.record_address, \
                token=token_challenge, key_authorization=key_authorization)
            challenge_http_server.start()



            # A client responds with an empty object ({}) to acknowledge that the
            # challenge can be validated by the server.
            self.acme_request(url_challenge, {}, True)
            self.poll_server(payload="", url=url_challenge) 

            challenge_http_server.terminate()
            challenge_http_server.join() #otherwise it might become a zombie process
            #self.dns_server.stop()

            
    def handle_dns01_challenge(self):
        for challenge in self.challenges:
            token_challenge = challenge['token']
            url_challenge = challenge['url']

            jwk_thumbprint = get_jwk_thumbprint(self)
            key_authorization = token_challenge + "." + jwk_thumbprint

            # The client then computes the SHA-256 digest [FIPS180-4]
            # of the key authorization. #Note: Here it difers from http-01 challenge

            hash_key_authorization = sha256(key_authorization.encode('utf-8')).digest()
            hash_key_authorization_bytes = b64_encode_bytes(hash_key_authorization)

            zone = "_acme-challenge." + challenge['domain'] + ". 300 IN TXT " + "\"" + hash_key_authorization_bytes + "\""
            self.dns_server = ACME_DNS_Server(zone, address="", port=10053)
            self.dns_server.start()

            # A client responds with an empty object ({}) to acknowledge that the
            # challenge can be validated by the server.
            self.acme_request(url=url_challenge, payload={}, kid_known=True)
            self.poll_server(payload="", url=url_challenge) 
            #self.dns_server.stop()


    def finalize_order(self):
        csr = construct_csr(self, self.domains, self.private_rsa_key_cert)
        csr_der = csr.public_bytes(Encoding.DER)
        csr = b64_encode(csr_der)
        payload = {'csr' : csr}
        resp = self.acme_request(self.finalize_url, payload=payload, kid_known=True)
        
        resp_dict = self.poll_server(payload="", url=self.order_url)
        self.url_signed_certificate = resp_dict['certificate']

    def dowload_certificate(self):
        resp = self.acme_request(self.url_signed_certificate, payload="", kid_known=True) 
        self.certificate_decoded = resp.content.decode('utf8')
        ## save certificate in state to be able to revoke later
        self.certificate = x509.load_pem_x509_certificate(resp.content, backend=default_backend()).public_bytes(Encoding.DER)  
        with open('cert.pem', "wb") as f:
            f.write(resp.content)


    def revoke_certificate(self):
        certificate_payload = b64_encode_bytes(self.certificate)
        payload = {'certificate' : certificate_payload}
        self.acme_request(self.revoke_cert_url, payload=payload, kid_known=True)

    def poll_server(self, payload, url):
        status = ""
        while status != "valid":
            resp_dict = self.acme_request(url, payload=payload, kid_known = True).json()
            status = resp_dict['status']
            time.sleep(3)
        return resp_dict

        

    def acme_request(self, url, payload, kid_known : bool):
        header = {"Content-Type" : "application/jose+json"}
        if kid_known == True:
            protected_header = {
                "alg": "RS256",
                "kid": self.kid,
                "nonce": self.new_nonce,
                "url": url
            }
        else:
            protected_header = {
                "alg": "RS256",
                "nonce": self.new_nonce,
                "url": url,
                "jwk": {
                    "kty": "RSA",
                    'n' : b64_encode_bytes(int_to_bytes(self.public_rsa_key.public_numbers().n)),
                    'e' : b64_encode_bytes(int_to_bytes(self.public_rsa_key.public_numbers().e)),
                    }
            }
        jws = generate_jws(payload, protected_header, self.private_rsa_key)
        resp = requests.post(url, data=jws, headers=header, verify='pebble.minica.pem')
        if "Replay-Nonce" in resp.headers:
            self.new_nonce = resp.headers['Replay-Nonce']
        return resp
        


    

### Helper Functions ### 

def get_jwk_thumbprint(acme_client):    
    jwk_json = json.dumps(acme_client.account_key, sort_keys=True, separators=(',', ':')).encode('utf-8') #sort_keys in lexical order and strip spaces for canonical json 
    hashed_jwk_json = sha256(jwk_json).digest()
    thumbprint = b64_encode_bytes(hashed_jwk_json)
    
    return thumbprint

def b64_encode_bytes(data : bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def b64_encode_str(str : str):
    data = str.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def b64_encode(data):
    if isinstance(data, str):
        return b64_encode_str(data)
    else:
        return b64_encode_bytes(data)

## round the nearest multiple of 8 to get correct number of bytes
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length()+8-1) // 8 * 8, 'big')
    
def generate_jws(payload, protected_header, signature_key):
    jws = {}
    # serialize to json object and then base64-encode it 
    serialized_protected_header = json.dumps(protected_header)
    encoded_header = b64_encode(serialized_protected_header)

    #payload non empty, first serialize to JSON string and encode
    if(payload != ""):
        payload = b64_encode(json.dumps(payload))

    msg_to_sign = encoded_header +  "." +  payload
    signature = signature_key.sign(msg_to_sign.encode('utf8'), padding.PKCS1v15(), hashes.SHA256())
    signature = b64_encode(signature)

    jws["protected"] = encoded_header
    jws["payload"] = payload
    jws["signature"] = signature

    jws = json.dumps(jws).encode('utf8')

    return jws 


#### CRYPTOGRAPHIC FUNCTIONS ####
def generate_rsa_private_key():
    private_rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_rsa_key

def construct_csr(client, domains, key):
    domain_names_x509 = []
    for domain in domains:
        domain_names_x509.append(x509.DNSName(domain))

    csr = (
        x509.CertificateSigningRequestBuilder()
            .subject_name(
                
                x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CH"),
                    x509.NameAttribute(x509.NameOID.JURISDICTION_LOCALITY_NAME, "ZH"),
                    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "ETHZ")
                ]
            )
        ).add_extension(
            x509.SubjectAlternativeName(domain_names_x509), critical=False
        ).sign(key, hashes.SHA256(), backend=default_backend())
    )

    return csr


def main():

    parser = argparse.ArgumentParser(description='ACME Client')
    parser.add_argument('challenge_type', choices=['dns01', 'http01'], help='ACME challenge type the client should perform.')
    parser.add_argument('--dir', type=str, required=True, help='Directory URL of the ACME Server')
    parser.add_argument('--record', type=str, help='IPv4 address which must be returned by DNS server for all A-record queries.')
    parser.add_argument('--domain', type=str, required=True, action='append', help='The domain for which to request the certificate.')
    parser.add_argument('--revoke', required=False, action='store_true', help='If present, immediately revoke the certificate after obtaining it.')

    args = parser.parse_args()



    acme_client = ACME_Client(args.dir, args.domain, args.record)

    acme_client.create_account()
    acme_client.submit_order(args.domain)

    acme_client.fetch_challenges(args.challenge_type)

    if args.challenge_type == "dns01":
        acme_client.handle_dns01_challenge()
    else:
        acme_client.handle_http01_challenge()
    
    acme_client.finalize_order()

    acme_client.dowload_certificate()

    if(args.revoke != None):
        acme_client.revoke_certificate()

    
    zone = ""
    for domain in args.domain:
        zone += domain + ". 60 A " + args.record + "\n"

    dns_server = ACME_DNS_Server(zone, "0.0.0.0", port=10053)
    dns_server.start()


    ##certificate server
    certificate_http_server = Cert_Https_Server(args.record, acme_client.certificate_decoded)
    certificate_http_server.start()


    ### shutdown server
    shutdown_server = Shutdown_Server()

    certificate_http_server.terminate()
    certificate_http_server.join() ## join again to avoid zombie process
    
    acme_client.dns_server.stop()
    dns_server.stop()
    

if __name__ == "__main__":
    main()











