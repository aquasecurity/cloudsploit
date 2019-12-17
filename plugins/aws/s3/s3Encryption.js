var minimatch = require('minimatch');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5
};

function statementDeniesUnencryptedObjects(statement, bucketResource) {
    if (!statement) return false;
    return (statement.Effect === 'Deny') &&
        (statement.Principal === '*') &&
        (Array.isArray(statement.Action)
            ? statement.Action.find(action => minimatch('s3:GetObject', action))
            : minimatch('s3:GetObject', statement.Action)
        ) &&
        (Array.isArray(statement.Resource)
            ? statement.Resource.find(resource => resource === `${bucketResource}/*`)
            : statement.Resource === `${bucketResource}/*`
        ) && (
            statement.Condition &&
            statement.Condition.Bool &&
            statement.Condition.Bool['aws:SecureTransport'] &&
            statement.Condition.Bool['aws:SecureTransport'] === 'false'
        );
}

function getEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
    title: 'S3 Bucket Encryption Enforcement',
    category: 'S3',
    description: 'All statements in all S3 bucket policies must have a condition that requires encryption at a certain level',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy'],
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

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        for (let bucket of listBuckets.data) {
            var bucketResource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2, 'No bucket policy found; encryption in transit not enforced', 'global', bucketResource);
                continue;
            }
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, 'global', bucketResource);
                continue;
            }

            try {
                var policyJson = JSON.parse(getBucketPolicy.data.Policy);
            } catch(e) {
                helpers.addResult(results, 3, `Bucket policy on bucket [${bucket.Name}] could not be parsed.`, 'global', bucketResource);
                continue;
            }
            if (!policyJson || !policyJson.Statement) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, 'global', bucketResource);
                continue;
            }
            if (!policyJson.Statement.length) {
                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption in transit not enforced', 'global', bucketResource);
                continue;
            }

            if (policyJson.Statement.find(statement => statementDeniesUnencryptedObjects(statement, bucketResource))) {
                helpers.addResult(results, 0, 'Bucket policy enforces encryption in transit', 'global', bucketResource);
            } else {
                helpers.addResult(results, 2, `Bucket does not enforce encryption in transit`, 'global', bucketResource);
            }
        }
        callback(null, results, source);
    }
};
