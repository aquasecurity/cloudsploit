var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Instance Pool Multiple AD',
    category: 'Compute',
    description: 'Determines if Instance Pools are launched in Multiple Availability Domains.',
    more_info: 'Launching Instance Pools in multiple availability domains follows best practices by creating highly available resources.',
    recommended_action: 'When launching instance pools, Add multiple availability domains.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm',
    apis: ['instancePool:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.instancePool, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instancePools = helpers.addSource(cache, source,
                    ['instancePool', 'list', region]);

                if (!instancePools) return rcb();

                if (instancePools.err || !instancePools.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Instance Pools: ' + helpers.addError(instancePools), region);
                    return rcb();
                };

                if (!instancePools.data.length) {
                    helpers.addResult(results, 0, 'No Instance Pools present', region);
                    return rcb();
                };

                instancePools.data.forEach(instancePool => {
                    if (instancePool.availabilityDomains &&
                        instancePool.availabilityDomains.length == 1) {
                            var myADs = Object.values(instancePool.availabilityDomains).join(', ');
                            helpers.addResult(results, 2, 
                                `Instance Pool is only in one Availability Domain: ${myADs}`, region, instancePool.id);
                    } else if (instancePool.availabilityDomains &&
                        instancePool.availabilityDomains.length > 1) {
                            var myADs = Object.values(instancePool.availabilityDomains).join(', ');
                            helpers.addResult(results, 0, 
                                `Instance Pool is in multiple Availability Domains: ${myADs}`, region, instancePool.id);
                    } else {
                        helpers.addResult(results, 0, 
                            'No Availability Domains', region, instancePool.id);
                    };
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};