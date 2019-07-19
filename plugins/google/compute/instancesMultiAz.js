var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instances Multi AZ',
    category: 'Compute',
    description: 'Ensures managed instances are regional for availability purposes.',
    more_info: 'Creating instances in a single zone creates a single point of failure for all systems in the VPC. All managed instances should be created as Regional to ensure proper failover.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Launch new instances as Regional Instance Groups.',
    apis: ['instanceGroups:aggregatedList', 'instances:compute:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instanceGroups, function(region, rcb){
            let instanceGroups = helpers.addSource(
                cache, source, ['instanceGroups', 'aggregatedList', region]);

            if (!instanceGroups) return rcb();

            if (instanceGroups.err || !instanceGroups.data) {
                helpers.addResult(results, 3, 'Unable to query Instance Groups: ' + helpers.addError(instanceGroups), region);
                return rcb();
            }
            if (!Object.keys(instanceGroups.data).length) {
                helpers.addResult(results, 0, 'No Instance Groups Found', loc);
                return lcb();
            };

            var groupName = [];
            async.each(instanceGroups.data, function (instanceGroup, icb) {
                if (instanceGroup.instanceGroups) {
                    instanceGroup.instanceGroups.forEach(group => {
                        if (group.region) {
                            groupName.push(group.name);
                        };
                    });
                } else {
                    icb();
                };
            });
            async.each(regions.instances.compute, function(location, loccb) {
                var instancesInRegion = 0;
                var regionExists = false;
                async.each(regions.zones[location], function (loc, lcb) {
                    let instances = helpers.addSource(
                        cache, source, ['instances', 'compute', 'list', loc]);    

                    if (!instances) return lcb();

                    if (instances.err || !instances.data) {
                        helpers.addResult(results, 3, 'Unable to query instances: ' + helpers.addError(instances), location);
                        return lcb();
                    };
        
                //Looping by zone, ignoring the results
                   if (!instances.data.length) {
                    // helpers.addResult(results, 0, 'No Instances Found', loc);
                    return lcb();
                   }
                    
                    async.each(instances.data, function(instance, incb) {
                        var instanceName = instance.name.split('-');
                        instanceName.splice(instanceName.length-1, 1);
                        instanceName = instanceName.join('-');

                        if (!groupName.includes(instanceName)) {
                            helpers.addResult(results, 2, 'The instance is only available in one zone' , location, instance.id);
                            instancesInRegion++;
                        } else {
                            regionExists = true;
                        }
                        incb();
                    })
                })
                if (!instancesInRegion && regionExists) {
                    helpers.addResult(results, 0, 'The instance Groups in the region are Highly Available' , location);
                } else if (!instancesInRegion && !regionExists) {
                    helpers.addResult(results, 0, 'No instances found in the region' , location);
                }
                loccb();
            })
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}