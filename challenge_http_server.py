from multiprocessing.context import Process
from flask.app import Flask


class Challenge_Http_Server(Process):
    def __init__(self, host, token, key_authorization) -> None:
        Process.__init__(self)
        self.host = host
        self.token = token
        self.key_authorization = key_authorization

    def run(self): #to enable threading when calling start()
        self.app = Flask(__name__)
        
        @self.app.route('/.well-known/acme-challenge/'+ self.token)

        def response():
            return self.key_authorization
        
        self.app.run(host=self.host, port=5002)

