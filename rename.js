var
	path = require('path'),
	fs = require('fs');

var
	DIR = './src/ios/include/cryptopp';

var dirs = fs.readdirSync(DIR);

var dirsMap = dirs.reduce(
	(a, f) => (a[f] = fs.readFileSync(path.join(DIR, f)).toString(), a),
	{}
);

var changed = {};

dirs.map((f) => {
	dirsMap[f] = dirsMap[f].replace(
		/#include "(.+\.h)"/g,
		function(all, includeExp) {
			if (dirsMap[includeExp]) {
				changed[f] = true;

				return '#include "lmn_' + includeExp + '"';
			} else {
				return all;
			}
		}
	);
});

dirs.map((f) => {
	if (!/^.*\.h$/.test(f)) {
		return;
	}

	fs.renameSync(
		path.join(DIR, f),
		path.join(DIR, 'lmn_' + f)
	);

	console.log(
		'\t\t<header-file src="src/ios/include/cryptopp/lmn_' + f + '" />'
	);

	if (changed[f]) {
		fs.writeFileSync(path.join(DIR, 'lmn_' + f), dirsMap[f]);
	}
});
