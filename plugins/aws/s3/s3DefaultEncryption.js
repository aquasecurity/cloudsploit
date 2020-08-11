var async = require('async');
var helpers = require('../../../helpers/aws');
const encryptionLevelMap = {
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5
};

function getEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
    title: 'S3 Encryption',
    category: 'S3',
    description: 'Ensures S3 bucket default encryption is configured at a level required by the organization.',
    more_info: '',
    recommended_action: 'Enable Default Encryption on S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'KMS:describeKey', 'KMS:listAliases', 'KMS:listKeys'],
    compliance: {},
    settings: {
        s3_encryption_level: {
            name: 'S3 Minimum Default Encryption Level',
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

        var desiredEncryptionLevelString = settings.s3_encryption_level || this.settings.s3_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.s3_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for S3 Default Encryption Level.');
            return callback(null, results, source);
        }

        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]
        var currentEncryptionLevelString, currentEncryptionLevel
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
                        'Error querying for bucket default Encryption for bucket: ' + bucket.Name +
                        ': ' + helpers.addError(getBucketEncryption),
                        'global', bucketResource);
                }
            } else {
                var algorithm = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
                if(algorithm === 'aws:kms' && desiredEncryptionLevel > 1) { //if only sse is required, reduce chance for errors and computation.
                    var getAliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
                    var getKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);
                    var keyArn = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID
                    if (keyArn.includes("alias/")) {
                        var aliasName = keyArn.slice(keyArn.search('alias/'), keyArn.length);
                        var queryAlias = getAliases.data.find(o => o.AliasName === aliasName);
                        if (!queryAlias){
                            helpers.addResult(results, 3, `Unable to locate KMS Alias for Bucket: ${bucket.Name} for alias: ` + aliasName, region, bucketResource);
                            return bcb();
                        }
                        var keyId = (getKeys.data.find(o => o.KeyId === queryAlias.TargetKeyId)).KeyId;
                        if (!keyId){
                            helpers.addResult(results, 3, `Unable to locate KMS Key for Bucket: ${bucket.Name} for alias: ` + queryAlias, region, bucketResource);
                            return bcb();
                        }
                    } else {
                        var keyId = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID.split("/")[1]
                    }

                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                    if(!describeKey) {
                        helpers.addResult(results, 3, `Unable to locate KMS key for Bucket: ${bucket.Name} for describeKey: ` + keyId, region, bucketResource);
                        return bcb();
                    }
                    if (describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)} for Bucket: ${bucket.Name}`, region, bucketResource);
                        return bcb();
                    }
                    currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata)
                } else {
                    currentEncryptionLevelString = 'sse'
                }
                currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString]
                if (currentEncryptionLevel < desiredEncryptionLevel) {
                    helpers.addResult(results, 1, `s3 is configured with default encryption at ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, bucketResource);
                } else {
                    helpers.addResult(results, 0, `s3 is configured with default encryption at a minimum of ${desiredEncryptionLevelString}`, region, bucketResource);
                }
            }
            return bcb();
        })
        callback(null, results, source);
    }
};