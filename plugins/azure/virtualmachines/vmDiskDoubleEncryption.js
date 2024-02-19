var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Disk Double Encryption',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that VM disks are encrypted at rest using both platform and customer managed keys.',
    more_info: 'Using double encryption for VM disks adds an extra layer of protection using a different encryption algorithm/mode at the infrastructure layer using platform managed encryption keys and provides an additional level of security if one of the keys is compromised.',
    recommended_action: 'Recreate VM disks with double encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption#double-encryption-at-rest',
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
                helpers.addResult(results, 3, 'Unable to query for disks: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disks found', location);
                return rcb();
            }
            for (let disk of disks.data) {
                if (!disk.id) continue;

                if (disk.encryption && disk.encryption.type && disk.encryption.type.toLowerCase() === 'encryptionatrestwithplatformandcustomerkeys'){
                    helpers.addResult(results, 0, 'VM disk is double encrypted using both platform and customer managed keys', location, disk.id);
                } else {
                    let message  = 'VM disk does not have double encryption enabled';
                    if (disk.encryption && disk.encryption.type) {
                        if (disk.encryption.type.toLowerCase() === 'encryptionatrestwithcustomerkey') {
                            message = 'VM disk is encrypted using only customer managed key';
                        } else if (disk.encryption.type.toLowerCase() === 'encryptionatrestwithplatformkey') {
                            message = 'VM disk is encrypted using only platform managed key';
                        } 
                    }
                    helpers.addResult(results, 2, message, location, disk.id);
                }

            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};