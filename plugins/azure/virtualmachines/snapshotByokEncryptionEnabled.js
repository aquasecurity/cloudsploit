var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Disk Snapshot BYOK Encryption Enabled',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Azure virtual machine disk snapshot have BYOK (Customer-Managed Key) encryption enabled.',
    more_info: 'Encrypting virtual machine disk snapshot helps protect and safeguard your data to meet organizational security and compliance commitments.',
    recommended_action: 'Modify affected snapshots and and enable customer managed key encryption.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption',
    apis: ['snapshots:list'],
    realtime_triggers: ['microsoftcompute:snapshots:write', 'microsoftcompute:snapshots:delete'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.snapshots, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['snapshots', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk snapshots: ' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No virtual machine disk snapshots found', location);
                return rcb();
            }

            for (let snapshot of snapshots.data) {

                if (!snapshot.id) continue;

                if (snapshot.encryption && snapshot.encryption.type && 
                    snapshot.encryption.type === 'EncryptionAtRestWithCustomerKey' ||
                    snapshot.encryption.type === 'EncryptionAtRestWithPlatformAndCustomerKeys') {
                    
                    helpers.addResult(results, 0, 'VM disk snapshot has BYOK encryption enabled', location, snapshot.id);
                } else {
                    helpers.addResult(results, 2, 'VM disk snapshot does not have BYOK encryption enabled', location, snapshot.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
 