'use strict';

var
	exec = require('cordova/exec'),
	cordova = require('cordova');

var LMNCrypto = function() {};

LMNCrypto.prototype.encryptFile = function(fin, fout, key, cb) {
	exec(
		function(res) {
			cb && cb(null, res);
		},
		function(err) {
			cb && cb(err);
		},
		"LMNCrypto",
		"encryptFile",
		[fin, fout, key]
	);
};

LMNCrypto.prototype.decryptFile = function(fin, fout, key, cb) {
	exec(
		function(res) {
			cb && cb(null, res);
		},
		function(err) {
			cb && cb(err);
		},
		"LMNCrypto",
		"decryptFile",
		[fin, fout, key]
	);
};

module.exports = new LMNCrypto();
