var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Snapshot Has Tags',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that Azure VM disk snapshots have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify affected snapshots and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['snapshots:list'],
    realtime_triggers: ['microsoftcompute:snapshots:write', 'microsoftcompute:snapshots:delete', 'microsoftresources:tags:write'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.snapshots, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['snapshots', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk snapshots: ' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No virtual machine disk snapshots found', location);
                return rcb();
            }
            for (let snapshot of snapshots.data) {

                if (!snapshot.id) continue;

                if (snapshot.tags && Object.entries(snapshot.tags).length > 0){
                    helpers.addResult(results, 0, 'VM disk snapshot has tags associated', location, snapshot.id);
                } else {
                    helpers.addResult(results, 2, 'VM disk snapshot does not have tags associated', location, snapshot.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
 