#!/usr/bin/env node

const fs = require('fs');
const net = require('net');
const child_process = require('child_process');
const crypto = require('crypto');
const webcrypto = crypto.webcrypto || new (require('@peculiar/webcrypto').Crypto)();
const subtle = webcrypto.subtle;

async function get_store_path(a, b, pipe_channel)
{
    var dir = 'cache/' + a + '/' + b;
    
    await fs.promises.mkdir(dir, {recursive: true});
    
    return dir + '/' + pipe_channel;
}

function generate_hash(buf)
{
    var hash = crypto.createHash('sha256');
    hash.update(buf);
    return hash.digest('hex');
}

function filter(str)
{
    return (str || '').replace(/[^a-z0-9-_]+/g, '');
}

async function keep_piping(fh, filename, socket, read_offset)
{
	const ac = global.AbortController ? new AbortController() : new (require('node-abort-controller').AbortController)();
    const watcher = await fs.watch(filename, {signal: ac.signal});
    watcher.on('change', function(event_type, event_filename)
    {
        read_next();
    });
    watcher.on('error', function(err)
    {
        console.error('error: Watcher failed (' + filename + '):', err);
        socket.destroy();
    });
    watcher.on('close', function()
    {
        if(socket.readyState === 'open')
        {
            // if watcher failed, but socket is still open, then destroy the socket
            socket.destroy();
        }
    });
    
    socket.on('close', function()
    {
        ac.abort();
    });
    
    // keep own track of position, because we specify a custom read_offset
    var position = read_offset || 0;
    
    async function read_next()
    {
		var buffer = Buffer.alloc(16384);
        while(true)
        {
            var result = await fh.read(buffer, 0, buffer.length, position || null);
            
            // note: we cannot use fifo/named-pipe because fh.read would block, and this cannot be aborted
            
            if(result.bytesRead === 0) return;
            
            position += result.bytesRead;
            
            socket.write(result.buffer.subarray(0, result.bytesRead));
        }
    }
    
    read_next();
}

const server = net.createServer(async function(socket)
{
    var clientPublicKey = null;
    var clientPublicKeyHash = null;
    var sessionKey = null;
    var challengeSuccess = false;
    
    var pipe_target = '';
    var pipe_channel = '';
    var pipe_read = false;
    var pipe_write = false;
    var pipe_read_offset = 0;
    
    socket.on('error', function(err)
    {
        console.error('error: Socket fail: ', err);
    });
    
    socket.on('close', function()
    {
        if(pipe_write && typeof pipe_write === 'object')
        {
            pipe_write.close();
        }
        if(pipe_read && typeof pipe_read === 'object')
        {
            // depending on readable stream or filehandle
            if(pipe_read.destroy)
            {
                pipe_read.destroy();
            }
            else
            {
                pipe_read.close();
            }
        }
    });
    
    // furthermore, the client must verify its own public key
    try
    {
        var rest = null;
        for await (const buffer of socket)
        {
            if(rest === null)
            {
                rest = buffer;
            }
            else
            {
                rest = Buffer.concat([rest, buffer]);
            }
            
            if(pipe_write)
            {
                pipe_write.write(rest);
                
                continue;
            }
            
            if(pipe_read) continue; // ignore any further input, but keep socket intact
            
            while(rest.length > 0)
            {
                var delimiterIndex = rest.indexOf('\n');
                if(delimiterIndex === -1)
                {
                    break;
                }
                
                var line = rest.subarray(0, delimiterIndex).toString('utf8').trim();
                rest = rest.subarray(delimiterIndex + 1);
                
				if(line.startsWith('pubkey '))
				{
					try
					{
						// assuming JWK formatted public key
						clientPublicKey = JSON.parse(line.substring('pubkey '.length).trim());
						
                    	// create a hash of the public key, for referencing
                    	// see: https://www.rfc-editor.org/rfc/rfc7638#section-3.5
                    	clientPublicKeyHash = generate_hash(JSON.stringify({
							e: clientPublicKey.e,
							kty: clientPublicKey.kty,
							n: clientPublicKey.n
						}));
						
						// todo: support for PEM and other formats
					}
					catch(err)
					{
						socket.write('warning: Parse error for JWK public-key.\n');
					}
                    socket.write('hash ' + clientPublicKeyHash + '\n');
				}
				
                // handle commands, the public key is known
                if(clientPublicKey !== null)
                {
                    // now we encrypt random bytes for the client, which must be able to decrypt it, to prove he owns the public key which was provided
                    if(sessionKey === null)
                    {
                        // generate random session key, 64 bytes is a 512-bit key
                        sessionKey = await new Promise((resolve, reject) => crypto.randomBytes(64, (err, buf) => err ? reject(err) : resolve(buf)));
                        
						var algorithm_map = {
							'RSA-OAEP-256': {name: 'RSA-OAEP', hash: 'SHA-256'}
						};
						
                        // encrypt random session key with public key of client
                        var cryptoClientPublicKey = await subtle.importKey(
							'jwk', // spki
							clientPublicKey, // Buffer.from(clientPublicKey.replace(/---.*?---\r?\n/g, ''), 'base64'),
							algorithm_map[clientPublicKey.alg],
							true,
							['encrypt']
						);
                        var challengeMessageArrayBuffer = await subtle.encrypt(
							algorithm_map[clientPublicKey.alg],
							cryptoClientPublicKey,
							sessionKey
						);
						// convert arraybuffer to buffer
                        var challengeMessageBuffer = Buffer.alloc(challengeMessageArrayBuffer.byteLength);
						var view = new Uint8Array(challengeMessageArrayBuffer);
						for(var i=0;i<challengeMessageBuffer.length;++i)
						{
							challengeMessageBuffer[i] = view[i];
						}
						//crypto.publicEncrypt({key: clientPublicKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, sessionKey);
						
                        // send ping with base64-encoded challenge
                        socket.write('ping ' + challengeMessageBuffer.toString('base64') + '\n');
                    }
                    else if(!challengeSuccess)
                    {
                        // the next line must be a challenge success
                        if(!line.startsWith('pong '))
                        {
                            socket.write('warning: Protocol error, input ignored. Please decrypt the Base64-encoded ping-message, reply with a Base64-encoded plaintext pong-message.\n');
                            socket.write('You wrote: ' + line + '!\n');
                        }
                        else
                        {
                            var challengeReply = Buffer.from(line.substring('pong '.length), 'base64');
                            
                            // use compare instead of equals to not leak info about the length of the session-key (although this is public information anyway)
                            if(sessionKey.compare(challengeReply) === 0)
                            {
                                challengeSuccess = true;
								socket.write('welcome\n'); // confirm authentication of ping challenge
                            }
                            else
                            {
                                socket.write('warning: Decryption error, try again. Pong message does not match encrypted ping message.\n');
                                socket.write('info: You sent: ' + challengeReply.toString('base64') + '.\n');
                            }
                        }
                    }
                    else
                    {
                        var args = line.split(/\s+/g);
                        var cmd = args[0];
                        
                        // public key is known, and client is proven to be the owner (beware, a middle-man not owning the private key, can still exist, therefore this client-server connection must use a TLS-certificate)
                        if(cmd === 'list')
                        {
                            // list users that put something in our home-directory
                            if(args.length === 1)
                            {
                                try
                                {
                                    for(const file of await fs.promises.readdir('cache/' + clientPublicKeyHash))
                                    {
                                        // skip hidden files/directories or specials
                                        if(file.startsWith('.')) continue;
                                        
                                        // todo: filter on if it is a directory?
                                        
                                        socket.write(file + '\n');
                                    }
									socket.write('\n'); // mark the end of the list
                                }
                                catch(err)
                                {
                                    if(err.code !== 'ENOENT')
                                    {
                                        throw err;
                                    }
                                    // else: no output when empty directory
                                }
                            }
                            // or list for a specific public-key all the files available
                            else
                            {
                                var target = filter(args[1]);
                                var dir = 'cache/' + clientPublicKeyHash + '/' + target;
                                
                                try
                                {
                                    for(const file of await fs.promises.readdir(dir))
                                    {
                                        // skip hidden files or specials
                                        if(file.startsWith('.')) continue;
                                        
                                        // maybe skip links/directories etc. only named pipes or files should be listed
                                        socket.write(file + '\t' + (await fs.promises.stat(dir + '/' + file)).size + '\n');
                                    }
									socket.write('\n'); // mark the end of the list
                                }
                                catch(err)
                                {
                                    if(err.code !== 'ENOENT')
                                    {
                                        throw err;
                                    }
                                    // else: no output when empty directory
                                }
                            }
                        }
                        else if(cmd === 'read')
                        {
                            pipe_target = filter(args[1]);
                            pipe_channel = filter(args[2] || '');
                            pipe_read = true;
                            pipe_read_offset = parseInt(args[3]) || 0;
                        }
                        else if(cmd === 'write')
                        {
                            pipe_target = filter(args[1]);
                            pipe_channel = filter(args[2] || '');
                            pipe_write = true;
                        }
                        else if(cmd === 'open')
                        {
                            pipe_target = filter(args[1]);
                            pipe_channel = filter(args[2] || '');
                            pipe_read = true;
                            pipe_write = true;
                            pipe_read_offset = parseInt(args[3]) || 0;
                        }
                        else
                        {
                            socket.write('warning: Invalid command (' + cmd + ')\n');
                        }
                        
                        if(pipe_read)
                        {
                            // write to socket whatever is new in the pipe_target...
                            // and asynchronously read from the file, and keep file open...
                            // file is clientpublickey/pipe_target/pipe_channel
                            var file = await get_store_path(clientPublicKeyHash, pipe_target, pipe_channel);
                            
                            try
                            {
                                // pipe_read = fs.createReadStream(file, {flags: fs.constants.O_RDWR});
                                pipe_read = await fs.promises.open(file, fs.constants.O_RDWR); // also writing, so that it doesn't block
                                
                                //console.error('client ' + clientPublicKeyHash + ' is opening ' + );
                                
                                keep_piping(pipe_read, file, socket, pipe_read_offset);
                            }
                            catch(err)
                            {
                                socket.write('error: Not found (' + pipe_channel + ').\n');
                                
                                pipe_target = '';
                                pipe_channel = '';
                                pipe_read = false;
                                pipe_write = false;
                                pipe_read_offset = 0;
                            }
                        }
                        
                        if(pipe_write)
                        {
                            // file is pipe_target/clientpublickey/pipe_channel
                            
                            // ensure directory, and get storage path for the given combination of public keys
                            var file = await get_store_path(pipe_target, clientPublicKeyHash, pipe_channel || ('default-' + Date.now()));
                            
                            // do not use fifo, because then we cannot know in advance how many bytes are ready for us
                            // and in case of connection errors, we cannot retry reading the data
                            
                            // open a write-stream to the file we want to write to
                            pipe_write = await fs.promises.open(file, 'a');
                        }
                        
                        // stop line-by-line reading
                        break;
                    }
                }
                // error: we first expect the client to provide their public key, before any other communication
                else
                {
                    socket.write('warning: Protocol error, input ignored. First provide your public key in JWK-format.\n');
                }
            }
        }
    }
    catch(err)
    {
        console.error(err);
        socket.end('error: Server exception.');
    }
});
server.on('error', function(err)
{
    throw err;
});
server.listen(7999, '127.0.0.1', function()
{
    console.log('Buffered Socket Server listening on ', server.address());
});
