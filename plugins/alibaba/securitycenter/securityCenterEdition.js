var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Security Center Edition',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensure that your cloud Security Center edition is Advanced or plus.',
    more_info: 'Premium Security Center editions like Advanced or Enterprise Edition provides crucial features liekthreat detection for network and endpoints, ' + 
        'providing malware detection, webshell detection and anomaly detection in Security Center.',
    link: 'https://www.alibabacloud.com/help/product/28498.htm',
    recommended_action: 'Upgrade your Security Center edition to at least Advanced.',
    apis: ['TDS:DescribeVersionConfig'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        // Below map might not be accurate as I checked with Anti-virus and Advanced editions and API is returning
        // 6 and 5 respectively against the version key. As it will be costly to try all editions to get the acrual
        // version key for all editions, I am taking an assumption and assuming this map so in future if there is
        // a contradict, this might be the issue.
        var versionIdNameMap = {
            1: 'Basic',
            2: 'Value-added Plan',
            3: 'Ultimate',
            4: 'Enterprise',
            5: 'Advanced',
            6: 'Anti-virus'
        };

        var describeVersionConfig = helpers.addSource(cache, source,
            ['tds', 'DescribeVersionConfig', region]);

        if (!describeVersionConfig) {
            return callback(null, results, source);
        }

        if (describeVersionConfig.err || !describeVersionConfig.data) {
            helpers.addResult(results, 3,
                `Unable to query Security Center version config: ${helpers.addError(describeVersionConfig)}`,
                region);
            return callback(null, results, source);
        }

        let securityVersion = describeVersionConfig.data.Version ? describeVersionConfig.data.Version : 1;

        if (securityVersion == 1 || securityVersion == 6) {
            helpers.addResult(results, 2, `Security Center edition is ${versionIdNameMap[securityVersion]}`, region);
        } else {
            helpers.addResult(results, 0, `Security Center edition is ${versionIdNameMap[securityVersion]}`, region);
        }

        callback(null, results, source);
    }
};