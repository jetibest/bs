#!/usr/bin/env node

const https = require('https');
const fs = require('fs');
const child_process = require('child_process');
const net = require('net');
const ws = require('ws');
const websocketstream = require('websocket-stream');

const server = https.createServer({
	cert: fs.readFileSync('tls/cert.pem'),
	key: fs.readFileSync('tls/key.pem')
});
const wss = new ws.WebSocketServer({
	server: server,
	perMessageDeflate: false
});

const p = child_process.spawn(
	'node',
	[
		'server.js',
		'--listen',
		'127.0.0.1',
		'7999'
	]
);
p.on('exit', process.exit);
p.stdout.pipe(process.stdout);
p.stderr.pipe(process.stderr);

wss.on('connection', function connection(ws)
{
	const socket = net.createConnection(7999);
	const stream = websocketstream(ws, {
		perMessageDeflate: false
	});
	socket.pipe(stream);
	stream.pipe(socket);
});

server.on('error', function(err)
{
	console.error(err);
});
server.listen(7998, '0.0.0.0', function()
{
    console.log('Buffered WebSocket Server listening on ', server.address());
});
