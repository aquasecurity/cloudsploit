var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CSEK Encryption Enabled',
    category: 'Compute',
    description: 'Ensure Customer Supplied Encryption Key Encryption is enabled on Disks',
    more_info: 'Google encrypts all disks at rest by default. By using CSEK only the users with the key can access the disk. Anyone else, including Google, cannot access the disk ensuring maximum security on the disk.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption',
    recommended_action: 'CSEK can only be configured when creating a disk, Delete the disk in question and redeploy with CSEK.',
    apis: ['disks:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.disks, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noDisks = {};
            var badDisks = [];
            var goodDisks = [];
            async.each(zones[region], function(zone, zcb) {
                var disks = helpers.addSource(cache, source,
                    ['disks', 'list', zone]);

                if (!disks) return zcb();

                if (disks.err || !disks.data) {
                    if (!myError[region]) {
                        myError[region] = [];
                    }
                    myError[region].push(zone);
                    return zcb();
                }

                if (!disks.data.length) {
                    if (!noDisks[region]) {
                        noDisks[region] = [];
                    }
                    noDisks[region].push(zone);
                    return zcb();
                }

                disks.data.forEach(disk => {
                    if (disk.creationTimestamp &&
                        disk.diskEncryptionKey &&
                        Object.keys(disk.diskEncryptionKey) &&
                        Object.keys(disk.diskEncryptionKey).length) {
                        goodDisks.push(disk.id)
                    } else if (disk.creationTimestamp) {
                        badDisks.push(disk.id)
                    }
                });
            });
            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query disks' , region);
            } else if (!goodDisks.length && !badDisks.length) {
                helpers.addResult(results, 0, 'No disks found in the region' , region);
            } else if (badDisks.length) {
                var myInstanceStr = badDisks.join(", ");
                helpers.addResult(results, 2,
                    `CSEK Encryption is disabled for the following disks: ${myInstanceStr}`, region);
            } else if (goodDisks.length) {
                helpers.addResult(results, 0,
                    'CSEK Encryption is enabled for all disks in the region', region);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};