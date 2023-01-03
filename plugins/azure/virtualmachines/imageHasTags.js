var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Old VM Disk Snapshots',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that virtual machines do not have older disk snapshots.',
    more_info: 'A snapshot is a full, read-only copy of a virtual hard drive (VHD). You can take a snapshot of an OS or data disk VHD to use as a backup, or to troubleshoot virtual machine (VM) issues. VM snapshots older than a specific period of time should be deleted to save cost of unused resources.',
    recommended_action: 'Ensure that there are no undesired old VM disk snapshots',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/snapshot-copy-managed-disk',
    apis: ['images:list'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.images, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['images', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk snapshots : ' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No existing virtual machine disk snapshots', location);
                return rcb();
            }
            for (let image of snapshots.data){
                if (!image.id) continue;

                if (image.tags.le)
            }


            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
 