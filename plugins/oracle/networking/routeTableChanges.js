var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Route Table Changes',
    category: 'Networking',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure an event rule is configured for route table changes.',
    more_info: 'Monitoring changes to route tables like create, update and delete will help in identifying changes to the traffic flows.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Events/Task/managingrules.htm',
    recommended_action: 'Configure an event rule for route table changes like create, update and delete.',
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
                    { displayName: 'Create', value: 'com.oraclecloud.virtualnetwork.createroutetable' },
                    { displayName: 'Update', value: 'com.oraclecloud.virtualnetwork.updateroutetable' },
                    { displayName: 'Delete', value: 'com.oraclecloud.virtualnetwork.deleteroutetable' },
                    { displayName: 'Change Compartment', value: 'com.oraclecloud.virtualnetwork.changeroutetablecompartment'}
                ];

                helpers.checkEventRules(rules.data, eventsToCheck, 'Route Table', compartment, region, results);
                
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};