var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Bucket CMK Encryption',
    category: 'Object Store',
    domain: 'Storage',
    severity: 'High',
    description: 'Ensure that Oracle Object Store buckets have encryption enabled using desired protection level.',
    more_info: 'By default, all object store buckets are encrypted using an Oracle-managed master encryption key. To have better control over how your object store buckets are encrypted, you can use Customer-Managed Keys (CMKs).',
    recommended_action: 'Ensure that all object store buckets have desired encryption level.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/encryption.htm',
    apis: ['namespace:get', 'bucket:list', 'bucket:get', 'vault:list', 'keys:list'],
    settings: {
        bucket_encryption_level: {
            name: 'Bucket Encryption Level',
            description: 'Desired protection level for Object store buckets. default: oracle-managed, cloudcmek: customer managed encryption keys, ' +
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

        let desiredEncryptionLevelStr = settings.bucket_encryption_level || this.settings.bucket_encryption_level.default;
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
                async.each(regions.bucket, function(region, rcb) {
                    if (helpers.checkRegionSubscription(cache, source, results, region)) {
                        var getBucket = helpers.addSource(cache, source,
                            ['bucket', 'get', region]);

                        if (!getBucket) return rcb();

                        if (getBucket.err || !getBucket.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for object store bucket details: ' + helpers.addError(getBucket), region);
                        } else if (!getBucket.data.length) {
                            helpers.addResult(results, 0, 'No object store bucket details to check', region);
                        } else {

                            getBucket.data.forEach(function(bucket) {

                                let currentEncryptionLevel =1; //default 

                                if (bucket.kmsKeyId) {
                                    currentEncryptionLevel = helpers.getProtectionLevel(keysObj[bucket.kmsKeyId], helpers.PROTECTION_LEVELS);
                                } 

                                let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];
    
                                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                    helpers.addResult(results, 0,
                                        `Object store bucket (${bucket.name})  has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, region, bucket.id);
                                } else {
                                    helpers.addResult(results, 2,
                                        `Object store bucket (${bucket.name})  has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, region, bucket.id);
                                }
                            });
                        }
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

