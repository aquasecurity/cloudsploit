var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Unmanaged Disk Encryption',
    category: 'Disks',
    description: 'Ensures that unmanaged disks are encrypted',
    more_info: "Encrypting unmanaged data disks (non-boot volume) ensures that the entire contents are fully unrecoverable without a key, protecting the volume from unwarranted reads.",
    recommended_action: 'Enable Data Disk Encryption on all unmanaged disks',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-disk-encryption',
    apis: ['disks:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.disks, function (location, rcb) {

            const disks = helpers.addSource(cache,source,
                ['disks', 'list', location]);

            if (!disks) return rcb();
                    
            if (disks.err || !disks.data) {
                helpers.addResult(results, 3,
                    'Unable to query disks: ' + helpers.addError(disks), location);
                return rcb();
            };

            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disks found', location);
                return rcb();
            };
            var isUnmanaged = false;

            disks.data.forEach(disk => {
                if (disk.managedBy) return;

                isUnmanaged = true;
                if (disk.encryptionSettings && disk.encryptionSettings.enabled) {
                    helpers.addResult(results, 0,
                        'Disk encryption is enabled on unmanaged disk', location, disk.id);
                } else {
                    helpers.addResult(results, 2,
                        'Disk encryption is not enabled on unmanaged disk', location, disk.id);
                };
            });
            if (!isUnmanaged) {
                helpers.addResult(results, 2, 'No unmanaged disks found', location);
            };

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
