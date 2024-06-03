from flask.app import Flask, request

class Shutdown_Server:    
    def __init__(self) -> None:
        self.app = Flask(__name__)
        @self.app.route('/shutdown',methods=['GET'])

        def shutdown_server():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'

        self.app.run(host="0.0.0.0", port=5003)
    