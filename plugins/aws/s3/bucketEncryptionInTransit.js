var helpers = require('../../../helpers/aws');

function statementDeniesInsecureTransport(statement, bucketResource) {
    if (!statement) return false;
    return (statement.Effect === 'Deny') &&
        (statement.Principal === '*') &&
        (Array.isArray(statement.Action)
            ? statement.Action.find(action => action === '*' || action === 's3:*')
            : (statement.Action === '*' || statement.Action === 's3:*')) &&
        Array.isArray(statement.Resource) &&
        statement.Resource.find(resource => resource === `${bucketResource}/*`) &&
        statement.Resource.find(resource => resource === bucketResource) &&
        (
            statement.Condition &&
            statement.Condition.Bool &&
            statement.Condition.Bool['aws:SecureTransport'] &&
            statement.Condition.Bool['aws:SecureTransport'] === 'false'
        );
}

module.exports = {
    title: 'S3 Bucket Encryption In Transit',
    category: 'S3',
    recommended_action: 'Add statement to bucket policy that denies all s3 actions. Resources must be list of bucket arn and bucket arn/*. The condition must equal { "Bool": { "aws:SecureTransport": "false" }',
    description: 'S3 bucket must have bucket policy statement the denies insecure transport (http)',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy'],

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
            console.log(JSON.stringify(getBucketPolicy, null, 2))

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
                // Parse the policy if it hasn't be parsed and replaced by another plugin....
                if (typeof getBucketPolicy.data.Policy === 'string') {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } else {
                    var policyJson = getBucketPolicy.data.Policy
                }
            } catch(e) {
                helpers.addResult(results, 3, `Bucket policy on bucket ${bucket.Name} could not be parsed.`, 'global', bucketResource);
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

            if (policyJson.Statement.find(statement => statementDeniesInsecureTransport(statement, bucketResource))) {
                helpers.addResult(results, 0, 'Bucket policy enforces encryption in transit', 'global', bucketResource);
            } else {
                helpers.addResult(results, 2, `Bucket does not enforce encryption in transit`, 'global', bucketResource);
            }
        }
        callback(null, results, source);
    }
};
