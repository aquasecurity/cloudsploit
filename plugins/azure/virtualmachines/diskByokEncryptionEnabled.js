var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Disk Volumes BYOK Encryption Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machine disks have BYOK (Customer-Managed Key) encryption enabled.',
    more_info: 'Encrypting virtual machine disk volumes helps protect and safeguard your data to meet organizational security and compliance commitments.',
    recommended_action: 'Ensure that virtual machine disks are created using BYOK encryption',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-key-vault',
    apis: ['disks:list'],

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

            async.each(disks.data, function(disk, scb) {
                if (disk.encryption && disk.encryption.type &&
                    (disk.encryption.type === 'EncryptionAtRestWithCustomerKey' ||
                    disk.encryption.type === 'EncryptionAtRestWithPlatformAndCustomerKeys')) {
                    helpers.addResult(results, 0, 'Disk volume has BYOK encryption enabled', location, disk.id);
                } else {
                    helpers.addResult(results, 2, 'Disk volume has BYOK encryption disabled', location, disk.id);
                }
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};