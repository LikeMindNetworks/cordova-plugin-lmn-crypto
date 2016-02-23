'use strict';

var
	exec = require('cordova/exec'),
	cordova = require('cordova');

var LMNCrypto = function() {};

LMNCrypto.prototype.decryptMessages = function(
		keyMap, messages, cb
) {
	exec(
		function(res) {
			cb && cb(null, res);
		},
		function(err) {
			cb && cb(err);
		},
		"LMNCrypto",
		"decryptMessages",
		[keyMap, messages]
	);
};

LMNCrypto.prototype.cipherFile = function(
		fin, fout, keyB64, ivB64, tagSize, cb
) {
	exec(
		function(res) {
			cb && cb(null, res);
		},
		function(err) {
			cb && cb(err);
		},
		"LMNCrypto",
		"cipherFile",
		[opType, fin, fout, keyB64, ivB64, tagSize]
	);
};

module.exports = new LMNCrypto();
