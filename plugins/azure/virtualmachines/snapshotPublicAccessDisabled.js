var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Disk Snapshot Public Access Disabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensures that Azure virtual machine disk snapshot are not publicly accessible.',
    more_info: 'A snapshot is a full, read-only copy of a virtual hard disk (VHD). You can use a snapshot as a point-in-time backup. Stopping public access to Snapshot ensure that your backups are protected at all times.',
    recommended_action: 'Modify snapshots and disable public access',
    link: 'https://learn.microsoft.com/en-us/azure/backup/security-overview',
    apis: ['snapshots:list'],
    realtime_triggers: ['microsoftcompute:snapshots:write', 'microsoftcompute:snapshots:delete'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.snapshots, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['snapshots', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for VM disk snapshots: ' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No VM disk snapshots found', location);
                return rcb();
            }
            for (let snapshot of snapshots.data) {
                if (!snapshot.id) continue;

                if (snapshot && snapshot.networkAccessPolicy &&
                 snapshot.networkAccessPolicy.toLowerCase() === 'allowprivate' || 
                 snapshot.networkAccessPolicy.toLowerCase() ===  'denyall') {
                    
                    helpers.addResult(results, 0, 'VM disk snapshot has public access disabled', location, snapshot.id);
                } else {
                    helpers.addResult(results, 2, 'VM disk snapshot does not have public access disabled', location, snapshot.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
 