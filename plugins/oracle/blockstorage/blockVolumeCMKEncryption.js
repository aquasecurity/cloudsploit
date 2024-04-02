var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume CMK Encryption',
    category: 'Block Storage',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that block volumes have encryption enabled using desired protection level.',
    more_info: 'By default, block volumes are encrypted using an Oracle-managed master encryption key. To have better control over the encryption process, you can use Customer-Managed Keys (CMKs).',
    recommended_action: 'Ensure all block volumes have desired encryption level.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Security/Reference/blockstorage_security.htm#data-encryption',
    apis: ['vault:list', 'keys:list', 'volume:list'],
    settings: {
        volume_encryption_level: {
            name: 'Block Volume Encryption Level',
            description: 'Desired protection level for block volumes. default: oracle-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key',
            regex: '^(default|cloudcmek|cloudhsm)$',
            default: 'cloudcmek'
        }
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var keysObj = {};

        let desiredEncryptionLevelStr = settings.volume_encryption_level || this.settings.volume_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        async.series([
            function (cb) {
                async.each(regions.keys, function (region, rcb) {
                    let keys = helpers.addSource(
                        cache, source, ['keys', 'list', region]);
                    if (keys && keys.data && keys.data.length) helpers.listToObj(keysObj, keys.data, 'id');
                    rcb();
                }, function () {
                    cb();
                });
            },
            function (cb) {
                async.each(regions.volume, function (region, rcb) {

                    if (helpers.checkRegionSubscription(cache, source, results, region)) {

                        var blockVolumes = helpers.addSource(cache, source,
                            ['volume', 'list', region]);

                        if (!blockVolumes) return rcb();

                        if (blockVolumes.err || !blockVolumes.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for block volumes: ' + helpers.addError(blockVolumes), region);
                            return rcb();
                        }

                        if (!blockVolumes.data.length) {
                            helpers.addResult(results, 0, 'No block volumes found', region);
                            return rcb();
                        }

                        blockVolumes.data.forEach(blockVolume => {
                            if (blockVolume.lifecycleState && blockVolume.lifecycleState === 'TERMINATED') return;

                            let currentEncryptionLevel = 1; //default 

                            if (blockVolume.kmsKeyId) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[blockVolume.kmsKeyId], helpers.PROTECTION_LEVELS);
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `Block volume (${blockVolume.displayName}) has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, region, blockVolume.id);
                            } else {
                                helpers.addResult(results, 2,
                                    `Block volume (${blockVolume.displayName}) has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, region, blockVolume.id);
                            }
                        });
                    }

                    rcb();
                }, function () {
                    cb();
                });
            }
        ], function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}