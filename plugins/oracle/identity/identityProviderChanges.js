var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Identity Provider Changes',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure an event rule is configured for Identity Provider changes.',
    more_info: 'Monitoring Identity Provider changes like create, update and delete will help in identifying changes to the security posture.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Events/Task/managingrules.htm',
    recommended_action: 'Configure an event rule for Identity Provider changes like create, update and delete.',
    apis: ['rules:list'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.rules, function(region, rcb) {
            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                var rules = helpers.addSource(cache, source,
                    ['rules', 'list', region]);

                if (!rules) return rcb();

                if (rules.err || !rules.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for rules: ' + helpers.addError(rules), region);
                    return rcb();
                }
                if (!rules.data.length) {
                    helpers.addResult(results, 2, 'No rules found', region);
                    return rcb();
                } 

                const compartment = rules.data[0].compartmentId;
                const eventsToCheck = [
                    { displayName: 'Create', value: 'com.oraclecloud.identitycontrolplane.createidentityprovider' },
                    { displayName: 'Update', value: 'com.oraclecloud.identitycontrolplane.updateidentityprovider' },
                    { displayName: 'Delete', value: 'com.oraclecloud.identitycontrolplane.deleteidentityprovider' }
                ];

                helpers.checkEventRules(rules.data, eventsToCheck, 'Identity Provider', compartment, region, results);
                
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};