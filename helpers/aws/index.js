var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var api = require('./api.js');
var api_multipart = require('./api_multipart.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');
var govRegionsFedRampEast1  = require('./regions_gov_fedramp_east_1.js');
var govRegionsFedRampWest1  = require('./regions_gov_fedramp_west_1.js');
var chinaRegions = require('./regions_china.js');

var regions = function(settings) {
    if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-east-1') return govRegionsFedRampEast1;
    if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-west-1') return govRegionsFedRampWest1;
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
for (var a in api) helpers[a] = api[a];
for (var am in api_multipart) helpers[am] = api_multipart[am];

module.exports = helpers;