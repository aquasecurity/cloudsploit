var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Unmanaged Disk Encryption',
    category: 'Disks',
    description: 'Ensure that unattached disks in a subscription are encrypted',
    more_info: "Encrypting your unmanaged Data disks (non-boot volume) ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads",
    recommended_action: 'Enable Data Disk Encryption on all Unmanaged Disks',
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
                    'Unable to query Disks: ' + helpers.addError(disks), location);
                return rcb();
            };

            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disks', location);
                return rcb();
            };
            var isUnmanaged = false;

            disks.data.forEach(disk => {
                if (disk.managedBy) {
                    return;
                };
                if (disk.encryptionSettings && disk.encryptionSettings.enabled) {
                    helpers.addResult(results, 0,
                        'Disk encryption is enabled on unmanaged disk',location, disk.id);
                    isUnmanaged = true;
                } else {
                    helpers.addResult(results, 2,
                        'Disk encryption is not enabled on unmanaged disk',location, disk.id);
                        isUnmanaged = true;
                };
            });
            if (!isUnmanaged) {
                helpers.addResult(results, 2, 'No Unmanaged Disks in the region.',location);
            };

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
