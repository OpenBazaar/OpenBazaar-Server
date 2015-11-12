__author__ = 'chris'
from OpenSSL import SSL
from twisted.internet import ssl


class ChainedOpenSSLContextFactory(ssl.DefaultOpenSSLContextFactory):

    def __init__(self, privateKeyFileName, certificateChainFileName,
                 sslmethod=SSL.SSLv23_METHOD):
        """
        @param privateKeyFileName: Name of a file containing a private key
        @param certificateChainFileName: Name of a file containing a certificate chain
        @param sslmethod: The SSL method to use
        """
        self.privateKeyFileName = privateKeyFileName
        self.certificateChainFileName = certificateChainFileName
        self.sslmethod = sslmethod
        self.cacheContext()
        ssl.DefaultOpenSSLContextFactory.__init__(self, privateKeyFileName,
                                                  certificateChainFileName, self.sslmethod)

    def cacheContext(self):
        ctx = SSL.Context(self.sslmethod)
        ctx.use_certificate_chain_file(self.certificateChainFileName)
        ctx.use_privatekey_file(self.privateKeyFileName)
        self._context = ctx
