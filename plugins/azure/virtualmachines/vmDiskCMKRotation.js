var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Disk CMK Rotation',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that customer-managed keys (CMK) are automatically rotated for virtual machine disks.',
    more_info: 'Automatic key rotation helps ensure your keys are secure. A disk references a key via its disk encryption set. When you enable automatic rotation for a disk encryption set, the system will automatically update all managed disks, snapshots, and images referencing the disk encryption set to use the new version of the key within one hour.',
    recommended_action: 'Enable automatic key rotation for all VM disk encryption sets.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption#automatic-key-rotation-of-customer-managed-keys',
    apis: ['disks:list','diskEncryptionSet:get'],
    realtime_triggers: ['microsoftcompute:disks:write','microsoftcompute:disks:delete','microsoftcompute:diskencryptionsets:write'],

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
          

            disks.data.forEach((disk) => {
                if (!disk.id) return;
               
                if (disk.encryption && disk.encryption.type &&
                    disk.encryption.type.toLowerCase() === 'encryptionatrestwithplatformkey') {
                    helpers.addResult(results, 0, 'Disk is encrypted using a platform managed key', location, disk.id);
                   
                } else {
                    if (disk.encryption && disk.encryption.diskEncryptionSetId) {

                        var diskEncryptionSet = helpers.addSource(cache, source, ['diskEncryptionSet', 'get', location, disk.id]);
                        
                        if (diskEncryptionSet && diskEncryptionSet.data && diskEncryptionSet.data.rotationToLatestKeyVersionEnabled) {
                            helpers.addResult(results, 0, 'Disk has automatic key rotation enabled', location, disk.id);
                        
                        } else {
                            helpers.addResult(results, 2, 'Disk does not have automatic key rotation enabled', location, disk.id);
                        }
                    }
                    
                        
                }
            });
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};