var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Autoscale Enabled',
    category: 'Compute',
    description: 'Ensure Autoscaling is enabled on Instance Pools.',
    more_info: 'Enabling Autoscale increases efficency and improves cost management for resources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/autoscalinginstancepools.htm',
    recommended_action: '1. Enter the Compute service. 2. On the left side select Autoscale Configurations 3. Create an autoscale configuration for all instance pools.',
    apis: ['instance:list','instancePool:list', 'autoscaleConfiguration:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var myInstancePools = [];

        async.each(regions.instancePool, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instancePools = helpers.addSource(cache, source,
                    ['instancePool', 'list', region]);

                if (!instancePools) return rcb();

                if ((instancePools.err && instancePools.err.length) || !instancePools.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instance Pools: ' + helpers.addError(instancePools), region);
                    return rcb();
                }; 

                if (!instancePools.data.length) {
                    helpers.addResult(results, 0,
                        'No Instance Pool found', region);
                };
                
                instancePools.data.forEach(instancePool => {
                    myInstancePools.push(instancePool.id)
                });
            };
            
            rcb();
        }, function() {
            if (!myInstancePools) {
                callback(null, results, source);
            };

            async.each(regions.autoscaleConfiguration, function(location, lcb){

                var autoscaleConfigs = helpers.addSource(cache, source,
                    ['autoscaleConfiguration', 'list', location]);

                if (!autoscaleConfigs) return lcb();

                if ((autoscaleConfigs.err && autoscaleConfigs.err.length) || !autoscaleConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Autoscale Configurations: ' + helpers.addError(autoscaleConfigs), location);
                    return lcb();
                }; 

                if (!autoscaleConfigs.data.length) {
                    return lcb();
                };

                autoscaleConfigs.data.forEach(autoscaleConfig => {
                    if (autoscaleConfig.isEnabled &&
                        autoscaleConfig.resource &&
                        autoscaleConfig.resource.id ) {
                        var ipIdx = myInstancePools.indexOf(autoscaleConfig.resource.id)
                        if (ipIdx > -1) {
                            myInstancePools.splice(ipIdx,1);
                        };
                    };
                });
                lcb();
            }, function() {
                if (myInstancePools.length) {
                    helpers.addResult(results, 2,
                        `These Instance Pools do not have Autoscale Configured: ${myInstancePools.join(', ')} `);
                } else {
                    helpers.addResult(results, 0,
                        'All Instance Pools have Autoscale Configured');
                };
                callback(null, results, source);
            });
        });
    }
};