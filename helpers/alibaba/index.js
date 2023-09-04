var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var chinaRegions = require('./regions_china.js');
var regRegions = require('./regions.js');

var regions = function(settings) {
    if (settings.china) return chinaRegions;
    return regRegions;
};

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6,
    ENCRYPTION_LEVELS: ['none', 'sse', 'cloudkms', 'alibabacmk', 'externalcmk', 'cloudhsm']
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
