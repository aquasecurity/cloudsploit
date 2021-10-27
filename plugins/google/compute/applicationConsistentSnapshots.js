var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Application Consistent Snapshots',
    category: 'Compute',
    description: 'Ensure that application consistent snapshots feature is enabled for snapshot schedules.',
    more_info: 'Application consistent snapshots are more reliable because they are created after making sure that current operations are temporarily ceased and any data in memory is flushed to disk.',
    link: 'https://cloud.google.com/compute/docs/disks/snapshot-best-practices#prepare_for_consistency',
    recommended_action: 'Ensure that all disk snapshot schedules are application consistent.',
    apis: ['resourcePolicies:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.resourcePolicies, (region, rcb) => {

            var resourcePolicies = helpers.addSource(cache, source,
                ['resourcePolicies', 'list', region]);

            if (!resourcePolicies) return rcb();

            if (resourcePolicies.err || !resourcePolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for snapshot schedules: ' + helpers.addError(resourcePolicies), region, null, null, resourcePolicies.err);
                return rcb();
            }

            if (!resourcePolicies.data.length) {
                helpers.addResult(results, 0, 'No snapshot schedules found', region);
                return rcb();
            }

            resourcePolicies.data.forEach(policy => {
                if (!policy.name) return;

                if (policy.snapshotSchedulePolicy.snapshotProperties && policy.snapshotSchedulePolicy.snapshotProperties.guestFlush) {
                    helpers.addResult(results, 0, 'Snapshot schedule is configured to take application-consistent snapshots',
                        region, policy.name);
                } else {
                    helpers.addResult(results, 2, 'Snapshot schedule is not configured to take application-consistent snapshots',
                        region, policy.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};