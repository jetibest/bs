class BufferedSocket extends EventTarget
{
	static subtle = window.crypto.subtle;
	
	static DEFAULT_HOST = 'localhost';
	static DEFAULT_PORT = 6273; // 'bs' == [0x62,0x73]
	
	static #str2ab(str)
	{
		const buf = new ArrayBuffer(str.length);
		const bufView = new Uint8Array(buf);
		for(let i=0,strLen=str.length;i<strLen;++i)
		{
			bufView[i] = str.charCodeAt(i);
		}
		return buf;
	}
	static #ab2str(buf)
	{
		return String.fromCharCode.apply(null, new Uint8Array(buf));
	}
	static async rsaDecrypt(options, ciphertext)
	{
		return BufferedSocket.#ab2str(
			await BufferedSocket.subtle.decrypt(
				{
					name: 'RSA-OAEP'
				},
				options.privateKey,
				typeof ciphertext === 'string' ? BufferedSocket.#str2ab(ciphertext) : ciphertext
			)
		);
	}
	static async rsaEncrypt(options, plaintext)
	{
		return BufferedSocket.#ab2str(
			await BufferedSocket.subtle.encrypt(
				{
					name: 'RSA-OAEP'
				},
				options.publicKey,
				typeof plaintext === 'string' ? BufferedSocket.#str2ab(plaintext) : plaintext
			)
		);
	}
	static async exportAsJWK(key)
	{
		return await BufferedSocket.subtle.exportKey('jwk', key);
	}
	
	privateKey = null;
	publicKey = null;
	ws = null;
	ws_buffer = new Uint8Array([]);
	pending = [];
	isConnected = false;
	
	async init(options)
	{
		options = options || {};
		
		// grab privateKey from options
		this.privateKey = this.privateKey || options.privateKey;
		if(options.keyPair && options.keyPair.privateKey) this.privateKey = this.privateKey || options.keyPair.privateKey;
		
		// import from JSON-string
		if(typeof this.privateKey === 'string')
		{
			this.privateKey = await BufferedSocket.subtle.importKey(
				'jwk',
				JSON.parse(this.privateKey),
				{
					name: 'RSA-OAEP',
					hash: 'SHA-256'
				},
				true,
				['decrypt']
			);
		}
		// import from JWK-object
		if(typeof this.privateKey === 'object' && this.privateKey !== null && !(this.privateKey instanceof CryptoKey))
		{
			this.privateKey = await BufferedSocket.subtle.importKey(
				'jwk',
				this.privateKey,
				{
					name: 'RSA-OAEP',
					hash: 'SHA-256'
				},
				true,
				[
					'decrypt'
				]
			);
		}
		// generate private key if not exists
		if(!this.privateKey)
		{
			const keyPair = await crypto.subtle.generateKey(
				{
					name: 'RSA-OAEP',
					modulusLength: 4096,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: 'SHA-256'
				},
				true,
				['encrypt', 'decrypt']
			);
			this.privateKey = keyPair.privateKey;
			this.publicKey = keyPair.publicKey;
		}
		// generate public key from private key if not exists
		if(!this.publicKey)
		{
			// get JWK public key from private key
			const jwk = await BufferedSocket.exportAsJWK(this.privateKey);
			// delete private part of this key
			delete jwk.d;
			delete jwk.dp;
			delete jwk.dq;
			delete jwk.q;
			delete jwk.qi;
			// set key options
			jwk.key_ops = ['encrypt'];
			// import key from JWK
			this.publicKey = await BufferedSocket.subtle.importKey(
				'jwk',
				jwk,
				{
					name: 'RSA-OAEP',
					hash: 'SHA-256'
				},
				true,
				['encrypt']
			);
		}
		
		var privkey_jwk = await BufferedSocket.exportAsJWK(this.privateKey);
		
		this.dispatchEvent(new CustomEvent(
			'init',
			{
				detail: {
					privateKeyJWK: privkey_jwk
				}
			}
		));
		
		return {
			privateKeyJWK: privkey_jwk
		};
	}
	async connect(options)
	{
		options = options || {};
		
		var self = this;
		
		var host = options.host || DEFAULT_HOST;
		var port = options.port || DEFAULT_PORT;
		
		var publicKeyJWK = await BufferedSocket.exportAsJWK(this.publicKey);
		var hash = '';
		var decoder = new TextDecoder();
		var hasError = false;
		
		return new Promise(function(resolve, reject)
		{
			self.isConnected = false;
			self.ws_buffer = new Uint8Array([]); // clear buffer
			self.pending = [];
			
			self.ws = new WebSocket('wss://' + host + ':' + port);
			self.ws.binaryType = 'arraybuffer';
			self.ws.onopen = function()
			{
				// send a public certificate in JWK-format
				self.ws.send('pubkey ' + JSON.stringify(publicKeyJWK) + '\n');
			};
			self.ws.onmessage = async function(evt)
			{
				var data = new Uint8Array(evt.data);
				var queue = new Uint8Array(self.ws_buffer.length + data.length);
				queue.set(self.ws_buffer);
				queue.set(data, self.ws_buffer.length);
				self.ws_buffer = queue;
				
				var lineIndex;
				while((lineIndex = queue.indexOf(10)) !== -1) // 10 == '\n'
				{
					var line = decoder.decode(queue.subarray(0, lineIndex)).trim();
					self.ws_buffer = queue = queue.subarray(lineIndex + 1);
					console.log('Received: ' + line);
					var args = line.split(/\s+/g);
					var cmd = args[0];
					if(cmd === 'hash')
					{
						hash = args[1];
					}
					else if(cmd === 'ping')
					{
						// decrypt challenge, if given, to prove that we own this public key
						if(args[1])
						{
							self.ws.send('pong ' + btoa(await BufferedSocket.rsaDecrypt({privateKey: self.privateKey}, atob(args[1]))) + '\n');
						}
						else
						{
							self.ws.send('pong\n');
						}
					}
					else if(cmd === 'welcome')
					{
						if(!self.isConnected)
						{
							self.isConnected = true;
							self.ws.onmessage = null; // detach handler after handshake
							self.dispatchEvent(new CustomEvent(
								'connect',
								{
									detail: {
										hash: hash
									}
								}
							));
							resolve({
								hash: hash
							});
							break;
						}
					}
					else
					{
						self.dispatchEvent(new CustomEvent(
							'error',
							{
								detail: {
									message: 'Received unknown command from server (' + cmd + ').',
									data: line
								}
							}
						));
					}
				}
			};
			self.ws.onerror = function(e)
			{
				self.isConnected = false;
				hasError = true;
				
				self.dispatchEvent(new CustomEvent(
					'error',
					{
						detail: {
							message: 'Connection with server broken.'
						}
					}
				));
			};
			self.ws.onclose = function(evt)
			{
				self.isConnected = false;
				self.ws.onmessage = null;
				
				// e.code, e.reason
				self.dispatchEvent(new CustomEvent(
					'close',
					{
						detail: {
							hasError: hasError,
							code: evt.code,
							reason: evt.reason
						}
					}
				));
			};
		});
	}
	async close()
	{
		if(this.isConnected && this.ws)
		{
			this.ws.close();
		}
	}
	
	async list(options)
	{
		options = options || {};
		
		var target = (options.target || '').trim();
		
		var self = this;
		
		return new Promise(function(resolve, reject)
		{
			var list = [];
			
			if(!self.isConnected)
			{
				reject(new Error('BufferedSocket: Not connected.'));
			}
			
			var closeHandler = function(evt)
			{
				if(evt.detail.hasError)
				{
					reject(new Error('BufferedSocket: Connection interrupted.'));
				}
				else
				{
					resolve(list);
				}
			};
			self.addEventListener('close', closeHandler);
			
			var decoder = new TextDecoder();
			self.ws.onmessage = async function(evt)
			{
				var data = new Uint8Array(evt.data);
				var queue = new Uint8Array(self.ws_buffer.length + data.length);
				queue.set(self.ws_buffer);
				queue.set(data, self.ws_buffer.length);
				self.ws_buffer = queue;
				
				var lineIndex;
				while((lineIndex = queue.indexOf(10)) !== -1) // 10 == '\n'
				{
					var line = decoder.decode(queue.subarray(0, lineIndex)).trim();
					self.ws_buffer = queue = queue.subarray(lineIndex + 1);
					
					if(!line)
					{
						self.ws.onmessage = null;
						self.removeEventListener('close', closeHandler);
						resolve(list);
						return;
					}
					
					var args = line.split(/\s+/g);
					if(!target)
					{
						var target_name = args[0];
						
						list.push({
							name: target_name
						});
					}
					else
					{
						var file_name = args[0];
						var file_size = parseInt(args[1]) || 0; // in bytes
						
						list.push({
							name: file_name,
							size: file_size
						});
					}
				}
			};
			self.ws_buffer = new Uint8Array([]);
			self.ws.send(target ? 'list ' + target + '\n' : 'list\n');
		});
	}
	async exec(options)
	{
		options = options || {};
		
		var command = (options.command || '').trim(); // read, write, open
		var target = options.target || ''; // hash of other person's pubkey
		if(typeof target === 'object') target = target.name;
		var filename = options.filename || '';
		if(typeof filename === 'object') filename = filename.name;
		var readOffset = parseInt(options.readOffset) || 0;
		
		if(!command || !target) throw new Error('BufferedSocket: Invalid usage of the exec() function.');
		
		var args = [
			command,
			target
		];
		if(filename)
		{
			args.push(filename);
			
			if(readOffset)
			{
				args.push(readOffset);
			}
		}
		
		var resolveFunction = null;
		var next = function(e)
		{
			if(resolveFunction === null)
			{
				self.pending.push(e);
			}
			else
			{
				var fn = resolveFunction;
				resolveFunction = null;
				fn(e);
			}
		};
		
		var self = this;
		self.addEventListener('close', evt =>
		{
			self.ws.onmessage = null;
			
			if(evt.detail.hasError)
			{
				next(new Error('BufferedSocket: Connection interrupted.'));
			}
			else
			{
				next(null);
			}
		});
		self.addEventListener('data', evt => next(evt.detail.data));
		
		self.ws.onmessage = function(evt)
		{
			self.dispatchEvent(new CustomEvent('data', {detail: {data: new Uint8Array(evt.data)}}));
		};
		self.pending = [];
		self.ws_buffer = new Uint8Array([]);
		self.ws.send(args.join(' ') + '\n');
		
		// use returned async iterator, or just manually listen for 'data' and 'close' events
		return {
			async *[Symbol.asyncIterator]()
			{
				var result;
				
				while(true)
				{
					result = await new Promise(resolve =>
					{
						if(self.pending.length > 0)
						{
							resolve(self.pending.shift());
						}
						else
						{
							resolveFunction = resolve;
						}
					});
					
					if(result === null) break; // EOF reached due to graceful closing of connection
					
					if(result instanceof Error) throw result; // error found
					
					yield result;
				}
			}
		};
	}
}
