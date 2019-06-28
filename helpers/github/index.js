var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');

var helpers = {};

for (s in shared) helpers[s] = shared[s];
for (f in functions) helpers[f] = functions[f];

module.exports = helpers;
