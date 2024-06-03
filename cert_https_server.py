from multiprocessing.context import Process
from flask.app import Flask


class Cert_Https_Server(Process):
    def __init__(self, host, certificate) -> None:
        Process.__init__(self)
        self.host = host
        self.certificate = certificate

    def run(self): #to enable threading when calling start()
        self.app = Flask(__name__)
        
        @self.app.route('/')

        def response():
            return self.certificate
        
        self.app.run(host="0.0.0.0", port=5001, ssl_context = ('cert.pem', 'pk.pem'))
