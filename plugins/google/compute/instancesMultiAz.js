var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instances Multi AZ',
    category: 'Compute',
    description: 'Ensures managed instances are regional for availability purposes.',
    more_info: 'Creating instances in a single zone creates a single point of failure for all systems in the VPC. All managed instances should be created as Regional to ensure proper failover.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Launch new instances as regional instance groups.',
    apis: ['instanceGroups:aggregatedList', 'instances:compute:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var region = regions.instanceGroups[0];

        let instanceGroups = helpers.addSource(cache, source,
            ['instanceGroups', 'aggregatedList', region]);

        if (!instanceGroups) {
            helpers.addResult(results, 3, 'Unable to query instance groups', region);
            return callback(null, results, source);
        } else if (instanceGroups.err || !instanceGroups.data) {
            helpers.addResult(results, 3, 'Unable to query instance groups: ' + helpers.addError(instanceGroups), region);
            return callback(null, results, source);
        } else {
            var groupName = [];
            async.each(instanceGroups.data, function (instanceGroup, icb) {
                if (instanceGroup.instanceGroups) {
                    instanceGroup.instanceGroups.forEach(group => {
                        if (group.region) {
                            groupName.push(group.name);
                        }
                    });
                }
                icb();
            }, function () {
                async.each(regions.instances.compute, function (location, loccb) {
                    var instancesInRegion = [];
                    var regionExists = false;
                    async.each(regions.zones[location], function (loc, lcb) {
                        let instances = helpers.addSource(
                            cache, source, ['instances', 'compute', 'list', loc]);

                        if (!instances) return lcb();

                        if (instances.err || !instances.data) {
                            helpers.addResult(results, 3, 'Unable to query instances: ' + helpers.addError(instances), location);
                            return lcb();
                        }

                        //Looping by zone, ignoring the results
                        if (!instances.data.length) {
                            // helpers.addResult(results, 0, 'No Instances Found', loc);
                            return lcb();
                        }

                        for (let instance of instances.data) {
                            var instanceName = instance.name.split('-');
                            instanceName.splice(instanceName.length - 1, 1);
                            instanceName = instanceName.join('-');

                            if (!groupName.includes(instanceName)) {
                                instancesInRegion.push(instance.id);
                            } else {
                                regionExists = true;
                            }
                        }
                        lcb();
                    }, function() {
                        if (instancesInRegion.length) {
                            var myInstancesStr = instancesInRegion.join(', ');
                            helpers.addResult(results, 2,
                                `These instances are only available in one zone: ${myInstancesStr}`, location);
                        } else if (!instancesInRegion.length && regionExists) {
                            helpers.addResult(results, 0, 'The instance groups in the region are highly available', location);
                        } else if (!instancesInRegion.length && !regionExists) {
                            helpers.addResult(results, 0, 'No instances found in the region', location);
                        }
                        loccb();
                    });
                }, function() {
                    callback(null, results, source);
                });
            });
        }
    }
};