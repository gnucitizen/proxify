var net = require('net');

/* ------------------------------------------------------------------------ */

String.prototype.ord = function () {
	return this.charCodeAt(0);
};

/* ------------------------------------------------------------------------ */

function Forwarder() {
	this.connection = null;
	this.firstLine = null;
	
	this.setupStage1();
}

Forwarder.prototype = {
	setupStage1: function () {
		this.handleData = this.handleData_firstLine;
	},
	
	setupStage2: function () {
		var match = this.firstLine.match(/^\w+\shttps?:\/\/(.*?)(?:\/|\s)/i);
		
		if (!match) {
			this.connection.destroy();
			
			return;
		}
		
		var hostport = match[1];
		var tokens = hostport.split(':');
		var host = tokens[0];
		var port = 0;
		
		if (tokens.length > 1) {
			port = parseInt(tokens[1], 10);
			
			if (isNaN(port) || port <= 0) {
				this.connection.destroy();
				
				return;
			}
		}
		
		if (port == 0) {
			if (this.firstLine.match(/^\w+\shttp:\/\//i)) {
				port = 80;
			} else
			if (this.firstLine.match(/^\w+\shttps:\/\//i)) {
				port = 443;
			} else {
				this.connection.destroy();
				
				return;
			}
		}
		
		var self = this;
		
		net.connect({host: host, port: port}, function (connection) {
			connection.on('data', function (data) {
				self.forwardData(connection, data);
			});
			
			connection.on('end', function () {
				self.forwardEnd(connection);
			});
		});
	},
	
	handleData_firstLine: function (connection, data) {
		this.connection = connection;
		
		var newLineC = '\n'.ord();
		var i = 0;
		
		while (i < data.length) {
			var c = data.readUInt8(i);
			
			if (c == newLineC) {
				this.firstLine = data.toString('ascii', 0, i);
				
				this.setupStage2();
				
				return;
			}
			
			i += 1;
		}
		
		// TODO: keep the buffer
	},
	
	handleData_rest: function (connection, data) {
		
	},
	
	handleData: function (connection, data) {
		throw new Error('not implemented');
	},
	
	handleEnd: function (connection) {
		// pass
	}
}

/* ------------------------------------------------------------------------ */

function handleConnection(connection) {
	var forwarder = new Forwarder();
	
	connection.on('data', function (data) {
		forwarder.handleData(connection, data);
	});
	
	connection.on('end', function () {
		forwarder.handleEnd(connection);
	});
}

/* ------------------------------------------------------------------------ */

var server = net.createServer(handleConnection);

server.listen(5050);
