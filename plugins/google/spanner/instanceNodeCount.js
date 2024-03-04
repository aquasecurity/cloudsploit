var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Spanner Instance Node Count',
    category: 'Spanner',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure than node count for Spanner instances is not above allowed count.',
    more_info: 'The number of provisioned Cloud Spanner instance nodes must be under desired limit to avoid reaching the limit and exceeding the set budget.',
    link: 'https://cloud.google.com/spanner/docs/instances',
    recommended_action: 'Modify Spanner instances to decrease number of nodes',
    apis: ['spanner:list'],
    settings: {
        spanner_allowed_instance_node_count: {
            name: 'Spanner Allowed Instance Node Count',
            description: 'The number of nodes allowed per one Spanner instance',
            regex: '^.*$',
            default: '20'
        }
    },
    realtime_triggers: ['spanner.admin.instance.InstanceAdmin.CreateInstance', 'spanner.admin.instance.InstanceAdmin.UpdateInstance', 'spanner.admin.instance.InstanceAdmin.DeleteInstance'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            spanner_allowed_instance_node_count: parseInt(settings.spanner_allowed_instance_node_count || this.settings.spanner_allowed_instance_node_count.default)
        };

        async.each(regions.spanner, function(region, rcb){
            let instances = helpers.addSource(cache, source,
                ['spanner', 'list', region]);

            if (!instances) return rcb();

            if (instances.err || !instances.data) {
                helpers.addResult(results, 3, 'Unable to query Spanner instances: ' + helpers.addError(instances), region, null, null, instances.err);
                return rcb();
            }

            if (!instances.data.length) {
                helpers.addResult(results, 0, 'No Spanner instances found', region);
                return rcb();
            }

            instances.data.forEach(spannerInstance => {
                if (!spannerInstance.name) return;

                let nodeCount = spannerInstance.nodeCount;
                if (!nodeCount && spannerInstance.processingUnits) {
                    nodeCount = Math.floor(spannerInstance.processingUnits/1000);
                }
                let resultStatus = (nodeCount <= config.spanner_allowed_instance_node_count) ? 0 : 2;

                helpers.addResult(results, resultStatus,
                    `Spanner instance has ${nodeCount} node of ${config.spanner_allowed_instance_node_count} limit`,
                    region, spannerInstance.name);
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};