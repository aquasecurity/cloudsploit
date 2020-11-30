var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');
var chinaRegions = require('./regions_china.js');

var regions = function(settings) {
    if (settings.govcloud) return govRegions;
    if (settings.china) return chinaRegions;
    return regRegions;
};

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6,
    CLOUDSPLOIT_EVENTS_BUCKET: 'cloudsploit-engine-trails',
    CLOUDSPLOIT_EVENTS_SNS: 'aqua-cspm-sns-'
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
