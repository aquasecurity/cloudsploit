var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Default Security List',
    category: 'Networking',
    description: 'Ensure the default security lists block all traffic by default',
    more_info: 'The default security list is often used for resources launched without a defined security list. For this reason, the default rules should be to block all traffic to prevent an accidental exposure.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securitylists.htm',
    recommended_action: 'Update the rules for the default security list to deny all traffic by default',
    apis: ['vcn:list', 'vcn:get', 'securityList:list'],
    compliance: {
        pci: 'PCI has strict requirements to segment networks using firewalls. ' +
            'Security lists are a software-layer firewall that should be used ' +
            'to isolate resources. Ensure default security lists to not allow ' +
            'unintended traffic to cross these isolation boundaries.'
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.vcn, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var vcn = helpers.addSource(cache, source,
                    ['vcn', 'list', region]);

                if (!vcn) return rcb();

                if (vcn.err) {
                    helpers.addResult(results, 3,
                        vcn.err.code + ": " + helpers.addError(vcn), region);
                    return rcb();
                }

                var getSecurityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (!getSecurityLists) return rcb();

                if (getSecurityLists.err && getSecurityLists.err.length > 0) {
                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' + helpers.addError(getSecurityLists), region);
                    return rcb();
                }

                if (!getSecurityLists.data || !getSecurityLists.data.length > 0) {
                    helpers.addResult(results, 0, 'No security lists present', region);
                    return rcb();
                }

                for (s in getSecurityLists.data) {
                    var sl = getSecurityLists.data[s];
                    for (l in sl) {
                        displayNameArr = sl.displayName.split(" ");
                        if (displayNameArr[0] === 'Default') {
                            if (sl.egressSecurityRules.length ||
                                sl.ingressSecurityRules) {
                                helpers.addResult(results, 2,
                                    'Default security list has ' + (sl.egressSecurityRules.length || '0') + ' inbound and ' + (sl.ingressSecurityRules.length || '0') + ' outbound rules',
                                    region, sl.vcnId);
                            } else {
                                helpers.addResult(results, 0,
                                    'Default security list does not have inbound or outbound rules',
                                    region, sl.vcnId);
                            }
                        }
                    }
                }
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};