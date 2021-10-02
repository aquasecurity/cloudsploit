var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Encryption',
    category: 'Storage',
    description: 'Ensure that Cloud Storage buckets have encryption enabled using desired protection level.',
    more_info: 'By default, all storage buckets are encrypted using Google-managed keys. To have better control over how your storage bucktes are encrypted, you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/storage/docs/encryption/customer-managed-keys',
    recommended_action: 'Ensure that all storage buckets have desired encryption level.',
    apis: ['buckets:list', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        bucket_encryption_level: {
            name: 'Storage Bucket Encryption Level',
            description: 'Desired protection level for Storage buckets. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.bucket_encryption_level || this.settings.bucket_encryption_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        var keysObj = {};

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        async.series([
            function(cb) {
                async.each(regions.cryptoKeys, function(region, rcb) {
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);
                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.buckets, function(region, rcb) {

                    let buckets = helpers.addSource(
                        cache, source, ['buckets', 'list', region]);

                    if (!buckets) return rcb();

                    if (buckets.err || !buckets.data) {
                        helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region, null, null, buckets.err);
                        return rcb();
                    }

                    if (!helpers.hasBuckets(buckets.data)) {
                        helpers.addResult(results, 0, 'No storage buckets found', region);
                        return rcb();
                    }
                    
                    var bucketFound = false;
                    if (buckets && buckets.data) {
                        buckets.data.forEach(bucket => {
                            if (!bucket.name) return;

                            bucketFound = true;
                            let resource = helpers.createResourceName('b', bucket.name);
                            let currentEncryptionLevel;

                            if (bucket && bucket.encryption && bucket.encryption.defaultKmsKeyName
                                && keysObj[bucket.encryption.defaultKmsKeyName]) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[bucket.encryption.defaultKmsKeyName], helpers.PROTECTION_LEVELS);
                            } else {
                                currentEncryptionLevel = 1; //default
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `Bucket has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                    region, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    `Bucket has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                    region, resource);
                            }
                        });
                    }
                    if (!bucketFound) {
                        helpers.addResult(results, 0, 'No storage buckets found', region);
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