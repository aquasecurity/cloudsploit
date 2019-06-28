var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');

var regions = function(govcloud) {
    if (govcloud) return govRegions;
    return regRegions;
};

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6
};

for (s in shared) helpers[s] = shared[s];
for (f in functions) helpers[f] = functions[f];

module.exports = helpers;
