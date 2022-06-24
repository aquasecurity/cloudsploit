var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'No Unattached Disk Volumes',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that the Azure virtual machines have no unattached disk volumes.',
    more_info: 'When a virtual machine (VM) in Azure is deleted, by default, any disks that are attached to the VM aren\'t deleted. Those disks need to be deleted to save cost for unused resources.',
    recommended_action: 'Ensure that there are no unattached virtual machine disk volumes',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/disks-find-unattached-portal',
    apis: ['disks:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb){

            var disks = helpers.addSource(cache, source, ['disks', 'list', location]);

            if (!disks) return rcb();

            if (disks.err || !disks.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk volumes: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disk volumes found', location);
                return rcb();
            }

            disks.data.forEach(disk => {
                if (disk.diskState && disk.diskState.toLowerCase() === 'attached') {
                    helpers.addResult(results, 0, 'Disk volume is attached to a virtual machine', location, disk.id);
                } else {
                    helpers.addResult(results, 2, 'Disk volume is not attached to a virtual machine', location, disk.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};