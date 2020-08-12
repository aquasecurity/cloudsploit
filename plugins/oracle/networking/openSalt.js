var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Open Salt',
    category: 'Networking',
    description: 'Determine if TCP ports 4505 or 4506 for the Salt master are open to the public',
    more_info: 'Active Salt vulnerabilities, CVE-2020-11651 and CVE-2020-11652 are exploiting Salt instances exposed to the internet. These ports should be closed immediately.',
    recommended_action: 'Restrict TCP ports 4505 and 4506 to known IP addresses',
    link: 'https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability',
    apis: ['vcn:list', 'securityList:list', 'networkSecurityGroup:list', 'securityRule:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var isSecurityRule = false;

        async.each(regions.securityList, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var ruleEmpty = false;
                var listEmpty = false;

                var ports = {
                    'tcp': [4505, 4506]
                };

                var service = 'Salt';

                var getSecurityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (getSecurityLists &&
                    getSecurityLists.err &&
                    getSecurityLists.err.length) {

                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' +
                        helpers.addError(getSecurityLists), region);

                } else if (getSecurityLists &&
                    (!getSecurityLists.data || !getSecurityLists.data.length)) {
                    listEmpty = true;

                } else if (getSecurityLists) {
                    helpers.findOpenPorts(getSecurityLists.data, ports,
                        service, region, results, isSecurityRule);
                }

                var getSecurityRules = helpers.addSource(cache, source,
                    ['securityRule', 'list', region]);

                if (getSecurityRules &&
                    getSecurityRules.err &&
                    getSecurityRules.err.length) {
                    helpers.addResult(results, 3,
                        'Unable to query for security rules: ' +
                        helpers.addError(getSecurityRules), region);

                } else if (getSecurityRules &&
                    (!getSecurityRules.data || !getSecurityRules.data.length)) {
                    ruleEmpty = true;

                } else if (getSecurityRules) {
                    var getSecurityGroups = helpers.addSource(cache, source,
                        ['networkSecurityGroup', 'list', region]);

                    isSecurityRule = true;

                    helpers.findOpenPorts(getSecurityRules.data, ports,
                        service, region, results, isSecurityRule, getSecurityGroups);
                }

                if (ruleEmpty && listEmpty) {
                    helpers.addResult(results, 0,
                        'No security rules or lists found', region);
                } else if (ruleEmpty) {
                    helpers.addResult(results, 0, 'No security rules found', region);
                } else if (listEmpty) {
                    helpers.addResult(results, 0, 'No security lists found', region);
                }
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};