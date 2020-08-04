var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regLocations = require('./locations.js');
var govLocations = require('./locations_gov.js');

var locations = function(govcloud) {
    if (govcloud) return govLocations;
    return regLocations;
};

var helpers = {
    locations: locations
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
