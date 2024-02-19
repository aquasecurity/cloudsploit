var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'User Changes',
    category: 'Identity',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure an event rule is configured for User changes.',
    more_info: 'Monitoring changes to users and their states and capabilities will help in identifying changes to the security posture.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Events/Task/managingrules.htm',
    recommended_action: 'Configure an event rule for changes to users and their states and capabilities.',
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
                    { displayName: 'Create', value: 'com.oraclecloud.identitycontrolplane.createuser' },
                    { displayName: 'Update', value: 'com.oraclecloud.identitycontrolplane.updateuser' },
                    { displayName: 'Delete', value: 'com.oraclecloud.identitycontrolplane.deleteuser' },
                    { displayName: 'Update User State', value: 'com.oraclecloud.identitycontrolplane.updateuserstate' },
                    { displayName: 'Update User Capabilities', value: 'com.oraclecloud.identitycontrolplane.updateusercapabilities' }
                ];

                helpers.checkEventRules(rules.data, eventsToCheck, 'User', compartment, region, results);
                
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};