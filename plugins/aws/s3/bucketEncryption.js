var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Encryption',
    category: 'S3',
    description: 'Ensures object encryption is enabled on S3 buckets',
    more_info: 'S3 object encryption provides fully-managed encryption of all objects uploaded to an S3 bucket.',
    recommended_action: 'Enable CMK KMS-based encryption for all S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        s3_encryption_require_cmk: {
            name: 'S3 Encryption Require CMK',
            description: 'When set to true S3 encryption using default KMS keys or AES will be marked as failing',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_encryption_require_cmk: settings.s3_encryption_require_cmk || this.settings.s3_encryption_require_cmk.default
        };

        config.s3_encryption_require_cmk = (config.s3_encryption_require_cmk == 'true');

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultKeyIds = [];
        var defaultKeyDesc = 'Default master key that protects my S3 objects';

        // Lookup the default master key for S3 if required
        if (config.s3_encryption_require_cmk) {
            async.each(regions.kms, function(region, rcb) {
                // List the KMS Keys
                var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

                if (!listKeys) return rcb();

                if (listKeys.err || !listKeys.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for KMS: ' + helpers.addError(listKeys), region);
                    return rcb();
                }

                if (!listKeys.data.length) return rcb();

                async.each(listKeys.data, function(key, kcb){
                    // Describe the KMS keys
                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

                    if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
                        var keyToAdd = describeKey.data.KeyMetadata;

                        if (keyToAdd.KeyManager && keyToAdd.KeyManager == 'AWS' && keyToAdd.Description &&
                            keyToAdd.Description.indexOf(defaultKeyDesc) === 0) {
                            defaultKeyIds.push(keyToAdd.Arn);
                        }
                    }
                    
                    kcb();
                }, function(){
                    rcb();
                });
            }, function(){
                checkBuckets();
            });
        } else {
            checkBuckets();
        }

        function checkBuckets() {
            var region = helpers.defaultRegion(settings);

            var listBuckets = helpers.addSource(cache, source,
                ['s3', 'listBuckets', region]);

            if (!listBuckets) return callback(null, results, source);

            if (listBuckets.err || !listBuckets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
                return callback(null, results, source);
            }

            if (!listBuckets.data.length) {
                helpers.addResult(results, 0, 'No S3 buckets to check');
                return callback(null, results, source);
            }

            listBuckets.data.forEach(function(bucket){
                var getBucketEncryption = helpers.addSource(cache, source,
                    ['s3', 'getBucketEncryption', region, bucket.Name]);

                if (getBucketEncryption && getBucketEncryption.err &&
                    getBucketEncryption.err.code && getBucketEncryption.err.code == 'ServerSideEncryptionConfigurationNotFoundError') {
                    helpers.addResult(results, 2,
                        'Bucket: ' + bucket.Name + ' has encryption disabled',
                        'global', 'arn:aws:s3:::' + bucket.Name);
                } else if (!getBucketEncryption || getBucketEncryption.err || !getBucketEncryption.data) {
                    helpers.addResult(results, 3,
                        'Error querying bucket encryption for: ' + bucket.Name +
                        ': ' + helpers.addError(getBucketEncryption),
                        'global', 'arn:aws:s3:::' + bucket.Name);
                } else if (getBucketEncryption.data.ServerSideEncryptionConfiguration &&
                        getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules &&
                        getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0] &&
                        getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault &&
                        getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm) {
                    var algo = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm;
                    var keyArn = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID;

                    if (config.s3_encryption_require_cmk &&
                        (algo == 'AES256' || (algo == 'aws:kms' && defaultKeyIds.indexOf(keyArn) > -1))) {
                        helpers.addResult(results, 2,
                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled but is not using a CMK',
                            'global', 'arn:aws:s3:::' + bucket.Name, custom);
                    } else {
                        helpers.addResult(results, 0,
                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled',
                            'global', 'arn:aws:s3:::' + bucket.Name, custom);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Bucket: ' + bucket.Name + ' has encryption disabled',
                        'global', 'arn:aws:s3:::' + bucket.Name);
                }
            });

            callback(null, results, source);
        }
    }
};
