var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'File Systems CMK Encryption',
    category: 'File Storage',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that OCI File Storage file systems have encryption enabled using desired protection level.',
    more_info: 'By default, OCI File Storage file systems are encrypted using an Oracle-managed master encryption key. To have better control over the encryption process, you can use Customer-Managed Keys (CMKs).',
    recommended_action: 'Ensure all file systems have desired encryption level.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/File/Concepts/filestorageoverview.htm#encryption',
    apis: ['vault:list', 'keys:list', 'fileSystem:list'],
    settings: {
        file_system_encryption_level: {
            name: 'File System Encryption Level',
            description: 'Desired protection level for File Storage file systems. default: oracle-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key',
            regex: '^(default|cloudcmek|cloudhsm)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var keysObj = {};

        let desiredEncryptionLevelStr = settings.file_system_encryption_level || this.settings.file_system_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        async.series([
            function(cb) {
                async.each(regions.keys, function(region, rcb) {
                    let keys = helpers.addSource(
                        cache, source, ['keys', 'list', region]);
                    if (keys && keys.data && keys.data.length) helpers.listToObj(keysObj, keys.data, 'id');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.fileSystem, function(region, rcb) {

                    if (helpers.checkRegionSubscription(cache, source, results, region)) {

                        var fileSystems = helpers.addSource(cache, source,
                            ['fileSystem', 'list', region]);

                        if (!fileSystems) return rcb();

                        if (fileSystems.err || !fileSystems.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for file systems: ' + helpers.addError(fileSystems), region);
                            return rcb();
                        }

                        if (!fileSystems.data.length) {
                            helpers.addResult(results, 0, 'No file systems found', region);
                            return rcb();
                        }

                        fileSystems.data.forEach(fileSystem => {
                            let currentEncryptionLevel = 1; //default 

                            if (fileSystem.kmsKeyId) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[fileSystem.kmsKeyId], helpers.PROTECTION_LEVELS);
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `File System (${fileSystem.displayName}) has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, region, fileSystem.id);
                            } else {
                                helpers.addResult(results, 2,
                                    `File System (${fileSystem.displayName}) has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, region, fileSystem.id);
                            }
                        });
                    }

                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
