var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Disk Snapshot Public Access Disabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machine disk snapshot are not publicly accessible.',
    more_info: 'Encrypting virtual machine disk snapshot helps protect and safeguard your data to meet organizational security and compliance commitments.',
    recommended_action: 'Modify snapshots and disable public access',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption',
    apis: ['snapshots:list'],

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
 