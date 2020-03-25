<<<<<<< HEAD
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
=======
var minimatch = require('minimatch');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    none: 0,
    sse: 1, // // x-amz-server-side-encryption:AES256
    awskms: 2, // x-amz-server-side-encryption:aws:kms without x-amz-server-side-encryption-aws-kms-key-id, implies any KMS key
    awscmk: 3, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is customer managed
    externalcmk: 4, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is externalcmk
    cloudhsm: 5, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is cloudhsm
};

function statementTargetsAction(statement, targetAction) {
    return Array.isArray(statement.Action)
        ? statement.Action.find(action => minimatch(targetAction, action))
        : minimatch(targetAction, statement.Action)
}

/**
 * Return the encryption level for the satement
 * If multiple conditions in StringNotEquals, return the least-restrictive condition found first (sse)
 */
function getEncryptionLevel(statement) {
    if (statement) {
        if (statement.Effect === 'Deny' && statement.Principal === '*') {
            if (statementTargetsAction(statement, 's3:PutObject')) {
                if (statement.Condition && statement.Condition.StringNotEquals) {
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption'] === 'AES256') {
                        return { level: 'sse' };
                    }
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption'] === 'aws:kms') {
                        return { level: 'awskms' };
                    }
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption-aws-kms-key-id']) {
                        return { key: statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption-aws-kms-key-id'] };
                    }
                }
            }
        }
    }
    return { level: 'off' }; // no encryption requirements on all s3:PutObject calls from everyone
}

function getKeyEncryptionLevel(kmsKey) {
>>>>>>> 50fcd6efd141b484db3d586bd8f8f1d5bc08af34
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
<<<<<<< HEAD
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
=======
    title: 'S3 Bucket Encryption Enforcement',
    category: 'S3',
    description: 'All statements in all S3 bucket policies must have a condition that requires encryption at a certain level',
    recommended_action: 'Configure a bucket policy to enforce encryption',
    link: 'https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        s3_required_encryption_level: {
            name: 'S3 Minimum Default Encryption Level',
>>>>>>> 50fcd6efd141b484db3d586bd8f8f1d5bc08af34
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

<<<<<<< HEAD
        var desiredEncryptionLevelString = settings.s3_encryption_level || this.settings.s3_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.s3_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for S3 Encryption Level.');
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
=======
        var desiredEncryptionLevelString = settings.s3_required_encryption_level || this.settings.s3_required_encryption_level.default
        console.log(desiredEncryptionLevelString)
        if(!desiredEncryptionLevelString.match(this.settings.s3_required_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for S3 Encryption Enforcement.');
            return callback(null, results, source);
        }

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
>>>>>>> 50fcd6efd141b484db3d586bd8f8f1d5bc08af34
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

<<<<<<< HEAD
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
                    currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata)
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
=======
        for (let bucket of listBuckets.data) {
            var bucketResource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2, 'No bucket policy found; encryption not enforced', 'global', bucketResource);
                continue;
            }
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, 'global', bucketResource);
                continue;
            }

            try {
                // Parse the policy if it hasn't been parsed and replaced by another plugin....
                if (typeof getBucketPolicy.data.Policy === 'string') {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } else {
                    var policyJson = getBucketPolicy.data.Policy
                }
            } catch(e) {
                helpers.addResult(results, 3, `Bucket policy on bucket [${bucket.Name}] could not be parsed.`, 'global', bucketResource);
                continue;
            }
            if (!policyJson || !policyJson.Statement) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, 'global', bucketResource);
                continue;
            }
            if (!policyJson.Statement.length) {
                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption not enforced', 'global', bucketResource);
                continue;
            }

            statementEncryptionLevels = policyJson.Statement.map(statement => {
                const encryptionLevel = getEncryptionLevel(statement);
                if (encryptionLevel.level) return encryptionLevel.level;
                if (encryptionLevel.key) {
                    const keyId = encryptionLevel.key.split('/')[1]
                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
                    if (!describeKey || describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
                        return 0;
                    }
                    return getKeyEncryptionLevel(describeKey.data.KeyMetadata);
                }
                return 0;
            });

            // get max encryption level string
            const currentEncryptionLevel = statementEncryptionLevels.reduce((max, level) => encryptionLevelMap[level] > encryptionLevelMap[max] ? level : max, 'none');

            if (encryptionLevelMap[currentEncryptionLevel] < encryptionLevelMap[desiredEncryptionLevelString]) {
                helpers.addResult(results, 2, `Bucket policy does not enforce encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, 'global', bucketResource);
            } else {
                helpers.addResult(results, 0, `Bucket policy enforces encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, 'global', bucketResource);
            }
        }
        callback(null, results, source);
    }
};
>>>>>>> 50fcd6efd141b484db3d586bd8f8f1d5bc08af34
