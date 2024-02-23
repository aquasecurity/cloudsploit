var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'VCN Inbound Security List',
    category: 'Networking',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensure all security lists have ingress rules configured.',
    more_info: 'To control network access to your instancesx, it is recommended that Virtual Cloud Networks (VCN) security lists are configured with ingress rules which provide stateful and stateless firewall capability.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm',
    recommended_action: 'Add ingress rules to all security lists.',
    apis: ['vcn:list', 'securityList:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.securityList, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var securityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (!securityLists || securityLists.err || !securityLists.data)  {
                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' + helpers.addError(securityLists), region);
                    return rcb();
                }
                if (!securityLists.data.length) {
                    helpers.addResult(results, 0, 'No security lists found', region);
                    return rcb();
                }

                securityLists.data.forEach(securityList => {
                    if (securityList.ingressSecurityRules && securityList.ingressSecurityRules.length) {
                        helpers.addResult(results, 0,
                            `Security list has ingress rules configured`, region, securityList.id);
                    }
                    else {
                        helpers.addResult(results, 2,
                            `Security list does not have ingress rules configured`, region, securityList.id);
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