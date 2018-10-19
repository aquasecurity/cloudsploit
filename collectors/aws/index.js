"use strict";

var fs        	= require("fs");
var path      	= require("path");
var collectors	= {};

var directories = fs.readdirSync(__dirname).filter(function(file) {
	return fs.statSync(path.join(__dirname, file)).isDirectory();
});

directories.forEach(function(directory, index) {
	collectors[directory] = {};

	fs
		.readdirSync(__dirname + '/' + directory)
		.filter(function(file) {
			return (file.indexOf(".") !== 0);
		})
		.forEach(function(file) {
			var collector = require(path.join(__dirname + '/' + directory, file));
			var name = file.substring(0, file.indexOf('.js'));
			collectors[directory][name] = collector;
		});
});

module.exports = collectors;