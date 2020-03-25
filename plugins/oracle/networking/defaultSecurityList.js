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
                var securityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (!securityLists) return rcb();

                if ((securityLists.err && securityLists.err.length > 0) || !securityLists.data ) {
                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' + helpers.addError(securityLists), region);
                    return rcb();
                }

                if (!securityLists.data.length) {
                    helpers.addResult(results, 0, 'No security lists found', region);
                    return rcb();
                }

                securityLists.data.forEach(securityList =>  {
                    if (securityList.displayName) {
                        var displayNameArr = securityList.displayName.split(" ");
                        if (displayNameArr[0] === 'Default') {
                            if ((securityList.egressSecurityRules &&
                                securityList.egressSecurityRules.length) ||
                                securityList.ingressSecurityRules) {
                                helpers.addResult(results, 2,
                                    'Default security list has ' + (securityList.egressSecurityRules.length || '0') + ' inbound and ' + (securityList.ingressSecurityRules.length || '0') + ' outbound rules',
                                    region, securityList.vcnId);
                            } else {
                                helpers.addResult(results, 0,
                                    'Default security list does not have inbound or outbound rules',
                                    region, securityList.vcnId);
                            }
                        }
                    }
                });
            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};