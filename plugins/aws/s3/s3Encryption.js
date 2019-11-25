var async = require('async');
var helpers = require('../../../helpers/aws');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'S3 Encryption',
    category: 'S3',
    description: 'Ensures S3 buckets are configured for Encryption at a level required by the organization.',
    more_info: '',
    recommended_action: 'Enable Encryption on S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'kms:describeKey'],
    compliance: {},
    settings: {
        s3_encryption_level: {
            name: 'S3 Minimum Encryption Level',
            description: 'In order (lowest to highest) \
                sse=Server-Side Encryption; \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'sse',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        const encryptionLevelMap = {
            sse: 1,
            awskms: 2,
            awscmk: 3,
            externalcmk: 4,
            cloudhsm: 5
        };

        var desiredEncryptionLevelString = settings.s3_encryption_level || this.settings.s3_encryption_level.default
        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]
        var currentEncryptionLevelString, currentEncryptionLevel
        if(!desiredEncryptionLevel) {
            helpers.addResult(results, 3, 'Settings misconfigured for SSM Encryption Level.');
            return callback(null, results, source);
        }

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

        async.each(listBuckets.data, function(bucket, bcb) {
            if (!bucket.Name) return bcb();

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;
            var getBucketEncryption = helpers.addSource(cache, source,
                ['s3', 'getBucketEncryption', region, bucket.Name]);

            if (!getBucketEncryption) {
                helpers.addResult(results, 3, 'Unable locate Bucket for getBucketEncryption: ' + bucket.Name, region, bucketResource);
                return bcb();
            }
            if (getBucketEncryption.err || !getBucketEncryption.data) {
                if(getBucketEncryption.err && getBucketEncryption.err.message === 'The server side encryption configuration was not found') {
                    helpers.addResult(results, 2,
                        'No default Encryption set for bucket: ' + bucket.Name,
                        'global', bucketResource);
                } else {
                    helpers.addResult(results, 3,
                        'Error querying for bucket Encryption for bucket: ' + bucket.Name +
                        ': ' + helpers.addError(getBucketEncryption),
                        'global', bucketResource);
                }
            } else {
                var algorithm = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
                if(algorithm === 'aws:kms' && desiredEncryptionLevel > 1) { //if only sse is required, reduce chance for errors and computation.
                    var keyId = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID.split("/")[1]
                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                    if(!describeKey) {
                        helpers.addResult(results, 3, 'Unable locate KMS key for describeKey: ' + keyId, region);
                        return bcb();
                    }
                    if (describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, 'Unable to query for KMS Key: ' + helpers.addError(describeKey), region);
                        return bcb();
                    }
                    currentEncryptionLevelString =  describeKey.data.KeyMetadata.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
                                                    describeKey.data.KeyMetadata.Origin === 'EXTERNAL' ? 'externalcmk' :
                                                    describeKey.data.KeyMetadata.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
                } else {
                    currentEncryptionLevelString = 'sse'
                }
                currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString]
                if (currentEncryptionLevel < desiredEncryptionLevel) {
                    helpers.addResult(results, 1, `s3 is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, bucketResource);
                } else {
                    helpers.addResult(results, 0, `s3 is encrypted to a minimum of ${desiredEncryptionLevelString}`, region, bucketResource);
                }
            }
            return bcb();
        })
        callback(null, results, source);
    }
};