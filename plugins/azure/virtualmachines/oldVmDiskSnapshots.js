var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Old VM Disk Snapshots',
    category: 'Virtual Machines',
    description: 'Ensures that virtual machines do not have older disk snapshots.',
    more_info: 'A snapshot is a full, read-only copy of a virtual hard drive (VHD). You can take a snapshot of an OS or data disk VHD to use as a backup, or to troubleshoot virtual machine (VM) issues. VM snapshots older than a specific period of time should be deleted to save cost of unused resources.',
    recommended_action: 'Ensure that there are no undesired old VM disk snapshots',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/snapshot-copy-managed-disk',
    apis: ['snapshots:list'],
    settings: {
        Days_Since_Snapshot_Creation: {
            name: 'Days since the creation of snapshot',
            description: 'The number of days since snapshot was created',
            regex: '^[0-9]*',
            default: '30'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            daysSinceCreation: parseInt(settings.Days_Since_Snapshot_Creation || this.settings.Days_Since_Snapshot_Creation.default)
        };

        async.each(locations.snapshots, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['snapshots', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk snapshots : ' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machine disk snapshots', location);
                return rcb();
            }

            async.each(snapshots.data, function(snapshot, scb) {
                const createdDate = new Date(snapshot.timeCreated);
                const dateNow = new Date();
                const diffTime = Math.abs(dateNow - createdDate);
                const daysCreated = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                if (daysCreated <= config.daysSinceCreation) {
                    helpers.addResult(results, 0, `VM disk snapshot is ${daysCreated} days older than ${config.daysSinceCreation} days desired limit`, location, snapshot.id);
                } else {
                    helpers.addResult(results, 2, `VM disk snapshot is ${daysCreated} days older than ${config.daysSinceCreation} days desired limit`, location, snapshot.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
 