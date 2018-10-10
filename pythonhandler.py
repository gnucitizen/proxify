#!/usr/bin/env python

import urllib2
import SocketServer
import BaseHTTPServer

class ThreadingHTTPServerMixIn(SocketServer.ThreadingMixIn):
        pass

class HTTPServer(ThreadingHTTPServerMixIn, BaseHTTPServer.HTTPServer):
	pass

class HTTPRedirectHandler(urllib2.HTTPRedirectHandler):
	def http_error_302(self, req, fp, code, msg, headers):
		return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)

	http_error_301 = http_error_303 = http_error_307 = http_error_302

class Request(urllib2.Request):
	def __init__(self, method, url, data, headers):
		self.method = method

		urllib2.Request.__init__(self, url, data, headers)

	def get_method(self):
		return self.method

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_GET(self):
		url = self.path

		print 'url is: %s' % repr(url)

		data = ''
		headers = self.headers
		request = Request('GET', url, data, headers)
		response = urllib2.urlopen(request)

		self.send_response(response.getcode())
		
		headers = response.info()

		for key in headers:
			self.send_header(key, headers[key])

		self.end_headers()

		self.wfile.write(response.read())

if __name__ == '__main__':
	opener = urllib2.build_opener(HTTPRedirectHandler)

	urllib2.install_opener(opener)

	server = HTTPServer(('localhost', 5050), Handler)

	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass

	server.server_close()
