var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Disk Public Access',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machine disks are not accessible publicly.',
    more_info: 'Private endpoints restrict the export and import of managed disks and more securely access data over a private link from clients on your Azure virtual network. The private endpoint uses an IP address from the virtual network address space for your managed disks. Network traffic between clients on their virtual network and managed disks only traverses over the virtual network and a private link on the Microsoft backbone network, eliminating exposure from the public internet.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-private-links-for-import-export-portal',
    recommended_action: 'Disable public access for all Azure virtual machine disks.',
    apis: ['disks:list'],
    realtime_triggers: ['microsoftcompute:disks:write', 'microsoftcompute:disks:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb) {

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
            for (let disk of disks.data) {
                if (!disk.id) continue;
                if (disk.networkAccessPolicy) {
                    if (disk.networkAccessPolicy.toLowerCase() === 'allowall') {
                        helpers.addResult(results, 2, 'Disk is publicly accessible', location, disk.id);
                        
                    } else if (disk.networkAccessPolicy.toLowerCase() === 'allowprivate') {
                        helpers.addResult(results, 0, 'Disk is privately accessible using private endpoints', location, disk.id);
                        
                    } else {
                        helpers.addResult(results, 0, 'Disk is not publicly or privately accessible', location, disk.id);
                        
                    }
                }
               

            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};