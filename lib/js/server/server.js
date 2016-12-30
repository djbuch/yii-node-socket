var express = require('express');

fs =    require('fs');
var serverConfiguration = require('./server.config.js');

var caFiles = [];
for (var i = 0, len = serverConfiguration.caFiles.length; i < len; i++) {
    caFiles.push(fs.readFileSync(serverConfiguration.caFiles[i]));
}

var options = {
    key:    fs.readFileSync(serverConfiguration.keyFile),
    cert:   fs.readFileSync(serverConfiguration.certFile),
    ca:     caFiles
};
var app = express();


var server = require('https').createServer(options,app);
var io = require('socket.io')(server);
var cookie = require('cookie');
var storeProvider = express.session.MemoryStore;
var sessionStorage = new storeProvider();

var componentManager = require('./components/component.manager.js');
componentManager.set('config', serverConfiguration);

var eventManager = require('./components/event.manager.js');
var socketPull = require('./components/socket.pull.js');
var db = require('./components/db.js');
db.init(serverConfiguration.dbOptions);

componentManager.set('db', db);
componentManager.set('sp', socketPull);
componentManager.set('io', io);
componentManager.set('eventManager', eventManager);
componentManager.set('sessionStorage', sessionStorage);

server.listen(serverConfiguration.port);//, serverConfiguration.host);
console.log('Listening ' + serverConfiguration.host + ':' + serverConfiguration.port);

//  accept all connections from local server
if (serverConfiguration.checkClientOrigin) {
    console.log('Set origin: ' + serverConfiguration.origin);
    io.set("origins", serverConfiguration.origin);
}

//  client
io.of('/client').use(function (socket, next) {
    var handshakeData = socket.request;

	if (!handshakeData.headers.cookie) {
		return next(new Error('NO COOKIE TRANSMITTED'));
	}

	handshakeData.cookie = cookie.parse(handshakeData.headers.cookie);

	var sid = handshakeData.cookie[serverConfiguration.sessionVarName];
	if (!sid) {
		next(new Error('Have no session id'));
	}

	handshakeData.sid = sid;
	handshakeData.uid = null;

	//  create write method
	handshakeData.writeSession = function (fn) {
		sessionStorage.set(sid, handshakeData.session, function () {
			if (fn) {
				fn();
			}
		});
	};

	//  trying to get session
	sessionStorage.get(sid, function (err, session) {

		//  create session handler
		var createSession = function () {
			var sessionData = {
				sid : sid,
				cookie : handshakeData.cookie,
				user : {
					role : 'guest',
					id : null,
					isAuthenticated : false
				}
			};

			//  store session in session storage
			sessionStorage.set(sid, sessionData, function () {

				//  authenticate and authorise client
				handshakeData.session = sessionData;
				next();
			});
		};

		//  check on errors or empty session
		if (err || !session) {
			if (!session) {

				//  create new session
				createSession();
			} else {

				//  not authorise client if errors occurred
				next(new Error('ERROR: ' + err));
			}
		} else {
			if (!session) {
				createSession();
			} else {

				//  authorize client
				handshakeData.session = session;
				handshakeData.uid = session.user.id;
				next();
			}
		}
	});

}).on('connection', function (socket) {

	//  add socket to pull
	socketPull.add(socket);

	//  connect socket to him channels
	componentManager.get('channel').attachToChannels(socket);

	//  bind events to socket
	eventManager.client.bind(socket);
});

//  server
io.of('/server').use(function (socket, next) {
	var data = socket.request;
	if (data && data.address) {
		if (data.headers['cookie']) {
			data.cookie = cookie.parse(data.headers.cookie);
			if (data.cookie.PHPSESSID) {
				data.sid = data.cookie.PHPSESSID;
				var found = false;
				for (var i in serverConfiguration.allowedServers) {
					console.log(i);
					console.log(serverConfiguration);
					if (serverConfiguration.allowedServers[i] == data.address.address) {
						found = true;
						break;
					}
				}
				if (found) {
					var createSession = function () {
						var sessionData = {
							sid : data.cookie.PHPSESSID,
							cookie : data.cookie,
							user : {
								role : 'guest',
								id : null,
								isAuthenticated : false
							}
						};

						//  store session in session storage
						sessionStorage.set(data.cookie.PHPSESSID, sessionData, function () {

							//  authenticate and authorise client
							data.session = sessionData;
							next();
						});
					};
					data.writeSession = function (fn) {
						sessionStorage.set(data.cookie.PHPSESSID, data.session, function () {
							if (fn) {
								fn();
							}
						});
					};
					sessionStorage.get(data.cookie.PHPSESSID, function (err, session) {
						if (err || !session) {
							if (!session) {
								createSession();
							} else {
								next(new Error('ERROR: ' + err));
							}
						} else {
							if (!session) {
								createSession();
							} else {

								//  authorize client
								data.session = session;
								data.uid = session.user.id;
								next();
							}
						}
					});
				} else {
					next(new Error('INVALID SERVER: server host ' + data.address.address + ' not allowed'));
					console.log(serverConfiguration.allowedServers);
				}
			} else {
				next(new Error('PHPSESSID is undefined'));
			}

		} else {
			next(new Error('No cookie'));
		}
	} else {
		next(new Error('NO ADDRESS TRANSMITTED.'));
		return false;
	}
}).on('connection', function (socket) {

	//  bind events
	eventManager.server.bind(socket);
});

componentManager.initCompleted();
