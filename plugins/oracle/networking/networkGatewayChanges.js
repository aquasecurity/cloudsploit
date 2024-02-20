var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Network Gateway Changes',
    category: 'Networking',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure an event rule is configured for network gateway changes.',
    more_info: 'Monitoring changes to Network Gateways like create, update and delete will help in identifying changes to the security posture.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Events/Task/managingrules.htm',
    recommended_action: 'Configure an event rule for network gateway changes like create, update and delete.',
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
                    { displayName: 'Create DRG', value: 'com.oraclecloud.virtualnetwork.createdrg' },
                    { displayName: 'Update DRG', value: 'com.oraclecloud.virtualnetwork.updatedrg' },
                    { displayName: 'Delete DRG', value: 'com.oraclecloud.virtualnetwork.deletedrg' },
                    { displayName: 'Create DRG Attachment', value: 'com.oraclecloud.virtualnetwork.createdrgattachment' },
                    { displayName: 'Update DRG Attachment', value: 'com.oraclecloud.virtualnetwork.updatedrgattachment' },
                    { displayName: 'Delete DRG Attachment', value: 'com.oraclecloud.virtualnetwork.deletedrgattachment' },
                    { displayName: 'Create Internet Gateway', value: 'com.oraclecloud.virtualnetwork.createinternetgateway' },
                    { displayName: 'Update Internet Gateway', value: 'com.oraclecloud.virtualnetwork.updateinternetgateway' },
                    { displayName: 'Delete Internet Gateway', value: 'com.oraclecloud.virtualnetwork.deleteinternetgateway' },
                    { displayName: 'Change Internet Gateway Compartment', value: 'com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment' },
                    { displayName: 'Create Local Peering Gateway', value: 'com.oraclecloud.virtualnetwork.createlocalpeeringgateway' },
                    { displayName: 'Update Local Peering Gateway', value: 'com.oraclecloud.virtualnetwork.updatelocalpeeringgateway' },
                    { displayName: 'Delete Local Peering Gateway - Begin', value: 'com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.begin' },
                    { displayName: 'Delete Local Peering Gateway - End', value: 'com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end' },
                    { displayName: 'Change Local Peering Gateway Compartment', value: 'com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment' },
                    { displayName: 'Create NAT Gateway', value: 'com.oraclecloud.natgateway.createnatgateway' },
                    { displayName: 'Update NAT Gateway', value: 'com.oraclecloud.natgateway.updatenatgateway' },
                    { displayName: 'Delete NAT Gateway', value: 'com.oraclecloud.natgateway.deletenatgateway' },
                    { displayName: 'Change NAT Gateway Compartment', value: 'com.oraclecloud.natgateway.changenatgatewaycompartment' },
                    { displayName: 'Attach Service Id', value: 'com.oraclecloud.servicegateway.attachserviceid' },
                    { displayName: 'Detach Service Id', value: 'com.oraclecloud.servicegateway.detachserviceid' },
                    { displayName: 'Create Service Gateway', value: 'com.oraclecloud.servicegateway.createservicegateway' },
                    { displayName: 'Update Service Gateway', value: 'com.oraclecloud.servicegateway.updateservicegateway' },
                    { displayName: 'Delete Service Gateway - Begin', value: 'com.oraclecloud.servicegateway.deleteservicegateway.begin' },
                    { displayName: 'Delete Service Gateway - End', value: 'com.oraclecloud.servicegateway.deleteservicegateway.end' },
                    { displayName: 'Change Service Gateway Compartment', value: 'com.oraclecloud.servicegateway.changeservicegatewaycompartment' },
                ];

                helpers.checkEventRules(rules.data, eventsToCheck, 'Network Gateway', compartment, region, results);
                
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};