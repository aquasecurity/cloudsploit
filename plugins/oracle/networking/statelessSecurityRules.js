var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Stateless Security Rules',
    category: 'Networking',
    description: 'Ensure all security rules are stateless.',
    more_info: 'Stateless security rules are one-way-rules that help mitigate ' +
        'DDoS attacks as well as speeding up network traffic.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm',
    recommended_action: 'Update all security rules to be stateless.',
    apis: ['vcn:list', 'securityList:list','networkSecurityGroup:list','securityRule:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.securityList, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var ruleEmpty = false;
                var listEmpty = false;

                var securityLists = helpers.addSource(cache, source,
                    ['securityList', 'list', region]);

                if (securityLists &&
                    securityLists.err &&
                    securityLists.err.length)  {

                    helpers.addResult(results, 3,
                        'Unable to query for security lists: ' +
                        helpers.addError(securityLists), region);

                } else if (securityLists &&
                    (!securityLists.data || !securityLists.data.length)) {
                    listEmpty = true;

                } else if (securityLists) {
                    var securityListStateless = true;
                    securityLists.data.forEach(securityList =>  {
                        var isStateless = true;
                        var statelessInt = 0;
                        if (securityList.ingressSecurityRules &&
                            securityList.ingressSecurityRules.length) {
                            securityList.ingressSecurityRules.forEach(securityRule => {
                                if (!securityRule.isStateless) {
                                    isStateless = false;
                                    statelessInt++;
                                }
                            });
                        }

                        if (!isStateless) {
                            helpers.addResult(results, 2,
                                `The security list has ${statelessInt} stateful security rules`,
                                region, securityList.id);

                            securityListStateless = false;
                        }
                    });

                }

                var securityGroups = helpers.addSource(cache, source,
                    ['networkSecurityGroup', 'list', region]);

                var securityRules = helpers.addSource(cache, source,
                    ['securityRule', 'list', region]);

                if (securityRules &&
                    securityRules.err &&
                    securityRules.err.length)  {
                    helpers.addResult(results, 3,
                        'Unable to query for security rules: ' +
                        helpers.addError(securityRules), region);
                    return rcb();

                } else if (securityRules &&
                    (!securityRules.data || !securityRules.data.length)) {
                    ruleEmpty = true;

                } else if (securityRules) {
                    var statefulNSGId = [];
                    var securityGroupName;
                    securityRules.data.forEach(securityRule => {
                        if (securityGroups &&
                            securityGroups.data.find(group => group.id === securityRule.networkSecurityGroups)) {
                            securityGroupName = securityGroups.data.find(group=> group.id === securityRule.networkSecurityGroups).displayName;
                        }

                        if(!securityRule.isStateless) {
                            if (statefulNSGId.indexOf(securityRule.networkSecurityGroups) < 0) {
                                helpers.addResult(results, 2,
                                    'The network security group' + (securityGroupName ? ': ' + securityGroupName : ' ') + ' has stateful security rules', region, securityRule.networkSecurityGroups);
                                statefulNSGId.push(securityRule.networkSecurityGroups);
                            }
                        }
                    });

                    if (!statefulNSGId.length && securityListStateless) {
                        helpers.addResult(results, 0,
                            'All network security groups and security lists have stateless security rules', region);
                    } else if (!statefulNSGId.length) {
                        helpers.addResult(results, 0,
                            'All network security groups have stateless security rules', region);
                    } else if (securityListStateless) {
                        helpers.addResult(results, 0,
                            'All security lists have stateless security rules', region);
                    }


                }
                if (ruleEmpty && listEmpty) {
                    helpers.addResult(results, 0, 'No security rules or lists found', region);
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