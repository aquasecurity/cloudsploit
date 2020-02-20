var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Autoscale Enabled',
    category: 'Compute',
    description: 'Ensures autoscaling is enabled on instance pools.',
    more_info: 'Enabling autoscaling increases efficiency and improves cost management for resources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/autoscalinginstancepools.htm',
    recommended_action: 'Enable autoscaling on all instance pools',
    apis: ['instance:list','instancePool:list', 'autoscaleConfiguration:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var badInstancePools = [];

        async.each(regions.instancePool, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instancePools = helpers.addSource(cache, source,
                    ['instancePool', 'list', region]);

                if (!instancePools) return rcb();

                if ((instancePools.err && instancePools.err.length) || !instancePools.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instance pools: ' + helpers.addError(instancePools), region);
                    return rcb();
                }

                if (!instancePools.data.length) {
                    helpers.addResult(results, 0,
                        'No instance pool found', region);
                }

                instancePools.data.forEach(instancePool => {
                    badInstancePools.push(instancePool.id)
                });
            }

            rcb();
        }, function() {
            if (!badInstancePools) {
                return callback(null, results, source);
            }

            async.each(regions.autoscaleConfiguration, function(location, lcb){

                if (helpers.checkRegionSubscription(cache, source, results, location)) {

                    var autoscaleConfigs = helpers.addSource(cache, source,
                        ['autoscaleConfiguration', 'list', location]);

                    if (!autoscaleConfigs) return lcb();

                    if ((autoscaleConfigs.err && autoscaleConfigs.err.length) || !autoscaleConfigs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for autoscaling configurations: ' + helpers.addError(autoscaleConfigs), location);
                        return lcb();
                    }

                    if (!autoscaleConfigs.data.length) {
                        return lcb();
                    }

                    autoscaleConfigs.data.forEach(autoscaleConfig => {
                        if (autoscaleConfig.isEnabled &&
                            autoscaleConfig.resource &&
                            autoscaleConfig.resource.id) {
                            if (badInstancePools.indexOf(autoscaleConfig.resource.id) > -1) {
                                badInstancePools.splice(badInstancePools.indexOf(autoscaleConfig.resource.id), 1);
                            }
                        }
                    });
                }
                lcb();
            }, function() {
                if (badInstancePools.length) {
                    helpers.addResult(results, 2,
                        `The following instance pools do not have autoscaling configured: ${badInstancePools.join(', ')} `);
                } else {
                    helpers.addResult(results, 0,
                        'All instance pools have autoscaling configured');
                }
                callback(null, results, source);
            });
        });
    }
};