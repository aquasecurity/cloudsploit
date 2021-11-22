var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Security Agent Installed',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensure that all assets are condifgured to be installed with Security Agent.',
    more_info: 'Security center provides a set of comprehensive endpoint intrusion detection and protection capabilities, ' +
        'such as remote logon detection, webshell detection and removal, anomaly detection, and detection of changes in key files and suspicious accounts in systems and applications. ' +
        'This requires an agent to be installed on the endpoint to work.',
    link: 'https://www.alibabacloud.com/help/doc-detail/111650.htm',
    recommended_action: 'Go to Security Center console, select Settings, click Agent, on Client to be installed tab, select all items, ' +
        'and click on One-click installation.',
    apis: ['TDS:DescribeFieldStatistics'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.tds, function(region, rcb) {
            var describeFieldStatistics = helpers.addSource(cache, source,
                ['tds', 'DescribeFieldStatistics', region]);

            if (!describeFieldStatistics) {
                return rcb();
            }

            if (describeFieldStatistics.err || !describeFieldStatistics.data) {
                helpers.addResult(results, 3,
                    `Unable to query TDS field statistics: ${helpers.addError(describeFieldStatistics)}`,
                    region);
                return rcb();
            }

            if (describeFieldStatistics.data.UnprotectedInstanceCount) {
                let msg = (describeFieldStatistics.data.UnprotectedInstanceCount == 1) ?
                    'There is 1 unprotected asset' : `There are ${describeFieldStatistics.data.UnprotectedInstanceCount} unprotected assets`;
                helpers.addResult(results, 2,
                    msg, region);
            } else {
                helpers.addResult(results, 0,
                    'There are no unprotected assets', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};