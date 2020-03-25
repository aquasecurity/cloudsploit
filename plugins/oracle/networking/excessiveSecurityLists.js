var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Excessive Security Lists',
    category: 'Networking',
    description: 'Determine if there are an excessive number of security lists in the account',
    more_info: 'Keeping the number of security lists to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security lists. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securitylists.htm',
    recommended_action: 'Limit the number of security lists to prevent accidental authorizations',
    apis: ['vcn:list','securityList:list'],
    settings: {
        excessive_security_lists_fail: {
            name: 'Excessive security lists Fail',
            description: 'Return a failing result when the number of security lists exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 40
        },
        excessive_security_lists_warn: {
            name: 'Excessive security lists Warn',
            description: 'Return a warning result when the number of security lists exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 30
        }
    },

    run: function (cache, settings, callback) {
        var config = {
            excessive_security_lists_fail: settings.excessive_security_lists_fail ||
                this.settings.excessive_security_lists_fail.default,
            excessive_security_lists_warn: settings.excessive_security_lists_warn ||
                this.settings.excessive_security_lists_warn.default
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.securityList, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var securityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (!securityLists) return rcb();

                if ((securityLists.err && securityLists.err.length > 0) || !securityLists.data ) {
                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' + helpers.addError(securityLists), region);
                    return rcb();
                }

                if (!securityLists.data.length > 0) {
                    helpers.addResult(results, 0, 'No security lists found', region);
                    return rcb();
                }

                var returnMsg = ' number of security lists: ' +
                    securityLists.data.length + ' groups found';

                if (securityLists.data.length > config.excessive_security_lists_fail) {
                    helpers.addResult(results, 2, 'Excessive' + returnMsg, region, null);
                } else if (securityLists.data.length > config.excessive_security_lists_warn) {
                    helpers.addResult(results, 1, 'Large' + returnMsg, region, null);
                } else {
                    helpers.addResult(results, 0, 'Acceptable' + returnMsg, region, null);
                }


            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};