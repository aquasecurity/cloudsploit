var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM OS Disk Encryption',
    category: 'Virtual Machines',
    description: 'Ensures that VM OS Disk Encryption is enabled for virtual machines',
    more_info: 'Encrypting VM OS disks (boot volume) ensures that the entire contents are fully unrecoverable without a key, protecting the volume from unwarranted reads.',
    recommended_action: 'Enable VM OS Disk Encryption on all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-disk-encryption',
    apis: ['disks:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'Enabling encryption of VM OS data helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
             'Encryption should be enabled for all VM OS disks storing this ' +
             'type of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb){

            var disks = helpers.addSource(cache, source, ['disks', 'list', location]);
            if (!disks) return rcb();
            if (disks.err || !disks.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Disks: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disks found', location);
            } else {
                var found = false;
                for(var i in disks.data) {
                    var disk = disks.data[i];
                    if (disk.name &&
                        disk.name.length &&
                        disk.name.toLowerCase().indexOf('osdisk') > -1) {
                        found = true;
                        if (disk.encryption) {
                            helpers.addResult(results, 0, 'OS disk encryption is enabled', location, disk.id);
                        } else {
                            helpers.addResult(results, 2, 'OS disk encryption is disabled', location, disk.id);
                        }
                    }
                }
                if (!found) {
                    helpers.addResult(results, 0, 'No OS disks found', location);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};