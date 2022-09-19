var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume CMK Encryption',
    category: 'Block Storage',
    domain: 'Storage',
    description: 'Ensures that boot volumes have encryption enabled using desired protection level.',
    more_info: 'By default, boot volumes are encrypted using an Oracle-managed master encryption key. To have better control over the encryption process, you can use Customer-Managed Keys (CMKs).',
    recommended_action: 'Ensure all boot volumes have desired encryption level.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Security/Reference/blockstorage_security.htm#data-encryption',
    apis: ['vault:list', 'keys:list', 'bootVolume:list'],
    settings: {
        volume_encryption_level: {
            name: 'Boot Volume Encryption Level',
            description: 'Desired protection level for boot volumes. default: oracle-managed, cloudcmek: customer managed encryption keys, ' +
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

        let desiredEncryptionLevelStr = settings.volume_encryption_level || this.settings.volume_encryption_level.default;
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
                async.each(regions.bootVolume, function(region, rcb) {

                    if (helpers.checkRegionSubscription(cache, source, results, region)) {

                        var bootVolumes = helpers.addSource(cache, source,
                            ['bootVolume', 'list', region]);

                        if (!bootVolumes) return rcb();

                        if (bootVolumes.err || !bootVolumes.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for boot volumes: ' + helpers.addError(bootVolumes), region);
                            return rcb();
                        }

                        if (!bootVolumes.data.length) {
                            helpers.addResult(results, 0, 'No boot volumes found', region);
                            return rcb();
                        }

                        bootVolumes.data.forEach(bootVolume => {
                            if (bootVolume.lifecycleState && bootVolume.lifecycleState === 'TERMINATED') return;

                            let currentEncryptionLevel = 1; //default 

                            if (bootVolume.kmsKeyId) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[bootVolume.kmsKeyId], helpers.PROTECTION_LEVELS);
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `Boot volume (${bootVolume.displayName}) has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, region, bootVolume.id);
                            } else {
                                helpers.addResult(results, 2,
                                    `Boot volume (${bootVolume.displayName}) has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, region, bootVolume.id);
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
