'use strict';

var
	exec = require('child_process').exec,
	del = require('del'),
	gulp = require('gulp'),
	decompress = require('gulp-decompress');

gulp.task('build', ['clean'], function() {
	gulp
		.src(['src/**/*', '!src/ios/lib/libcryptopp.a.zip'])
		.pipe(gulp.dest('build/src'));

	gulp
		.src(['www/**/*'])
		.pipe(gulp.dest('build/www'));

	gulp
		.src(['plugin.xml', 'package.json'])
		.pipe(gulp.dest('build'));

	gulp
		.src('src/ios/lib/libcryptopp.a.zip')
		.pipe(decompress())
		.pipe(gulp.dest('build/src/ios/lib'));
});

gulp.task('clean', function(callback) {
	return del(['build'], callback);
});

gulp.task('publish', ['clean', 'build'], function(callback) {
	exec(
		'npm publish ./build',
		{
			cwd: __dirname
		},
		callback
	);
});
