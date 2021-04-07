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
    CLOUDSPLOIT_EVENTS_SNS: 'aqua-cspm-sns-',
    ENCRYPTION_LEVELS: ['none', 'sse', 'awskms', 'awscmk', 'externalcmk', 'cloudhsm'],
    IAM_CONDITION_OPERATORS: {
        string: {
            Allow: ['StringEquals', 'StringEqualsIgnoreCase', 'StringLike'],
            Deny: ['StringNotEquals', 'StringNotEqualsIgnoreCase', 'StringNotLike']
        },
        arn: {
            Allow: ['ArnEquals', 'ArnLike'],
            Deny: ['ArnNotEquals', 'ArnNotLike']
        },
        ipaddress: {
            Allow: 'IpAddress',
            Deny: 'NotIpAddress'
        }
    },
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
