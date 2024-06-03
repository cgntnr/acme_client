from dnslib.server import DNSServer
from dnslib.zoneresolver import ZoneResolver
from dnslib.fixedresolver import FixedResolver

class ACME_DNS_Server:
    
    def __init__(self, zone, address, port):
        self.resolver = FixedResolver(zone)
        self.server = DNSServer(self.resolver, address="0.0.0.0", port=port)

    def start(self):
        self.server.start_thread()

    def stop(self):
        self.server.stop()

