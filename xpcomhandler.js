var CC = Components.classes;
var CI = Components.interfaces;

/* ------------------------------------------------------------------------ */

Components.utils.import('resource://gre/modules/XPCOMUtils.jsm');

/* ------------------------------------------------------------------------ */

var isDone = false;

/* ------------------------------------------------------------------------ */

function ProxifyProcessor() {
	this.threadManager = CC['@mozilla.org/thread-manager;1'].getService(CI.nsIThreadManager);
	this.ioService = CC['@mozilla.org/network/io-service;1'].getService(CI.nsIIOService);
	this.data = '';
	this.areHeadersSent = false;
}

ProxifyProcessor.prototype = {
	QueryInterface: XPCOMUtils.generateQI([CI.nsIInputStreamCallback]),
	
	/* -------------------------------------------------------------------- */
	
	init: function (transport, inputStream, outputStream) {
		this.transport = transport;
		this.inputStream = inputStream;
		this.outputStream = outputStream;
	},
	
	/* -------------------------------------------------------------------- */
	
	process: function () {
		this.inputStream.asyncWait(this, 0, 0, this.threadManager.currentThread);
	},
	
	/* -------------------------------------------------------------------- */
	
	onInputStreamReady: function (inputStream) {
		let amount = 0;
		
		try {
			amount = this.inputStream.available();
		} catch (e) {
			this.inputStream.close();
			this.outputStream.close();
			
			return;
		}
		
		let binaryInputStream = CC['@mozilla.org/binaryinputstream;1'].createInstance(CI.nsIBinaryInputStream);
		
		binaryInputStream.setInputStream(this.inputStream);
		
		this.data += binaryInputStream.readBytes(amount);
		
		let crlfPossition = this.data.indexOf('\r\n\r\n');
		
		if (crlfPossition < 0) {
			// TODO: make sure that the data structure is not already too big
			this.process();
			//
		} else {
			let head = this.data.substring(0, crlfPossition + 4);
			this.data = this.data.substring(crlfPossition + 4, this.data.length);
			
			try {
				this.handleRequest(head);
			} catch (e) {
				dump(e + '\n');
				this.inputStream.close();
				this.outputStream.close();
			}
		}
	},
	
	/* -------------------------------------------------------------------- */
	
	handleRequest: function (head) {
		let crlfPossition = head.indexOf('\r\n');
		let headLine = head.substring(0, crlfPossition);
		let headLineTokens = headLine.split(' ').map(function (token) { return token.trim(); });
		
		if (headLineTokens.length != 3) {
			this.inputStream.close();
			this.outputStream.close();
			
			return;
		}
		
		let method = headLineTokens[0];
		let location = headLineTokens[1];
		let version = headLineTokens[2];
		let headers = head.substring(crlfPossition + 2, head.length - 4);
		let uri = this.ioService.newURI(location, null, null);
		let channel = this.ioService.newChannelFromURI(uri);
		let httpChannel = channel.QueryInterface(CI.nsIHttpChannel);
		
		httpChannel.requestMethod = method;
		
		let headersLines = headers.split('\r\n');
		let headersLinesLength = headersLines.length;
		
		for (let i = 0; i < headersLinesLength; i += 1) {
			let tokens = headersLines[i].split(':').map(function (token) {
				return token.trim();
			});
			
			httpChannel.setRequestHeader(tokens[0], tokens[1], false);
		}
		
		let uploadChannel = httpChannel.QueryInterface(CI.nsIUploadChannel);
		let stringInputStream = CC['@mozilla.org/io/string-input-stream;1'].createInstance(CI.nsIStringInputStream);
		
		stringInputStream.setData('\r\n' + this.data, this.data.length + 2);
		
		let multiplexInputStream = CC['@mozilla.org/io/multiplex-input-stream;1'].createInstance(CI.nsIMultiplexInputStream);
		
		multiplexInputStream.appendStream(stringInputStream);
		
		try {
			if (this.inputStream.available() != 0) {
				multiplexInputStream.appendStream(this.inputStream);
			}
		} catch (e) {
			// pass
		}
		
		uploadChannel.setUploadStream(multiplexInputStream, null, -1);
		
		httpChannel.requestMethod = method;
		
		channel.notificationCallbacks = this;
		
		channel.asyncOpen(this, null);
	},
	
	/* -------------------------------------------------------------------- */
	
	getInterface: function (iid) {
		return this.QueryInterface(iid);
	},
	
	/* -------------------------------------------------------------------- */
	
	onStartRequest: function (request, context) {
		// pass
	},
	
	onStopRequest: function (request, context, statusCode) {
		this.outputStream.write('0\r\n\r\n', 5);
		
		this.inputStream.close();
		this.outputStream.close();
	},
	
	onDataAvailable: function (request, context, inputStream, offset, count) {
		let binaryInputStream = CC['@mozilla.org/binaryinputstream;1'].createInstance(CI.nsIBinaryInputStream);
		
		binaryInputStream.setInputStream(inputStream);
		
		let data = binaryInputStream.readBytes(count);
		
		if (!this.areHeadersSent) {
			let httpChannel  = request.QueryInterface(CI.nsIHttpChannel);
			let headersLines = ['Transfer-Encoding: chunked'];
			
			httpChannel.visitResponseHeaders({visitHeader: function (name, value) {
				if (name in {'Content-Encoding':1, 'Content-Length':1, 'Transfer-Encoding':1}) {
					return;
				}
				
				headersLines.push(name + ': ' + value);
			}});
			
			headersLines = headersLines.join('\r\n') + '\r\n';
			
			data = 'HTTP/1.1 ' + httpChannel.responseStatus + ' ' + httpChannel.responseStatusText + '\r\n' + headersLines + '\r\n' + data.length.toString(16) + '\r\n' + data + '\r\n';
			
			this.areHeadersSent = true;
		} else {
			data = data.length.toString(16) + '\r\n' + data + '\r\n';
		}
		
		if (this.transport.isAlive()) {
			this.outputStream.write(data, data.length);
		}
	},
	
	/* -------------------------------------------------------------------- */
	
	onProgress: function (request, context, progress, progressMax) {
		// pass
	},
	
	onStatus: function (request, context, status, statusArg) {
		// pass
	},
	
	/* -------------------------------------------------------------------- */
	
	onRedirect: function (httpChannel, newChannel) {
		newChannel.cancel(CR.NS_OK);
		
		let data = '';
		let headersLines = [];
		
		httpChannel.visitResponseHeaders({visitHeader: function (name, value) {
			if (name in {'Content-Encoding': 1, 'Content-Length': 1, 'Transfer-Encoding': 1}) {
				return;
			}
			
			headersLines.push(name + ': ' + value);
		}});
		
		headersLines = headersLines.join('\r\n') + '\r\n';
		
		data = 'HTTP/1.1 ' + httpChannel.responseStatus + ' ' + httpChannel.responseStatusText + '\r\n' + headersLines + '\r\n' + data.length.toString(16) + '\r\n' + data + '\r\n';
		
		this.areHeadersSent = true;
		
		if (this.transport.isAlive()) {
			this.outputStream.write(data, data.length);
		}
		
		this.inputStream.close();
		this.outputStream.close();
	}
};

/* ------------------------------------------------------------------------ */

let DEFAULT_BACKLOG = 50;
let DEFAULT_SEGMENT_SIZE = 8192;
let DEFAULT_SEGMENT_COUNT = 1024;

function ProxifyServer() {
	this.serverSocket = CC['@mozilla.org/network/server-socket;1'].createInstance(CI.nsIServerSocket);
}

ProxifyServer.prototype = {
	classDescription : 'Proxify Server',
	classID          : Components.ID('{c32c7e10-cf3a-11df-bd3b-0800200c9a66}'),
	contractID       : '@proxy.weaponry.gnucitizen.org/proxify-server;1',
	QueryInterface   : XPCOMUtils.generateQI([CI.IProxifyServer, CI.nsIServerSocketListener]),
	
	/* -------------------------------------------------------------------- */
	
	init: function (port, backlog, isLoopback) {
		this.serverSocket.init(port, isLoopback, backlog);
	},
	
	/* -------------------------------------------------------------------- */
	
	start: function () {
		this.serverSocket.asyncListen(this);
	},
	
	stop: function () {
		this.serverSocket.close();
	},
	
	/* -------------------------------------------------------------------- */
	
	onSocketAccepted: function (serverSocket, transport) {
		let inputStream = transport.openInputStream(0, DEFAULT_SEGMENT_SIZE, DEFAULT_SEGMENT_COUNT);
		let outputStream = transport.openOutputStream(0, DEFAULT_SEGMENT_SIZE, DEFAULT_SEGMENT_COUNT);
		let asyncInputStream = inputStream.QueryInterface(CI.nsIAsyncInputStream);
		let proxifyProcessor = new ProxifyProcessor();
		
		proxifyProcessor.init(transport, asyncInputStream, outputStream);
		proxifyProcessor.process();
	},
	
	onStopListening: function (serverSocket, status) {
		// pass
	}
};

/* ------------------------------------------------------------------------ */

let s = new ProxifyServer();

s.init(5050, 4, false);
s.start();

/* ------------------------------------------------------------------------ */

let workingDir = CC['@mozilla.org/file/directory_service;1'].getService(CI.nsIProperties).get('Home', Components.interfaces.nsIFile);
let proxifyFile = CC['@mozilla.org/file/local;1'].createInstance(CI.nsILocalFile);

proxifyFile.initWithFile(workingDir);
proxifyFile.appendRelativePath('Documents');
proxifyFile.appendRelativePath('Code');
proxifyFile.appendRelativePath('proxify');
proxifyFile.appendRelativePath('svn');
proxifyFile.appendRelativePath('trunk');
proxifyFile.appendRelativePath('obj');
proxifyFile.appendRelativePath('proxify');

let process = CC['@mozilla.org/process/util;1'].createInstance(CI.nsIProcess);

process.init(proxifyFile);

let parameters =  ['-p', '8080', '-P', '5050'];

process.run(false, parameters, parameters.length);

/* ------------------------------------------------------------------------ */

let threadManager = CC['@mozilla.org/thread-manager;1'].getService(CI.nsIThreadManager);
let mainThread = threadManager.currentThread;

while (!isDone) {
	mainThread.processNextEvent(true);
}

while (mainThread.hasPendingEvents()) {
	mainThread.processNextEvent(true);
}
