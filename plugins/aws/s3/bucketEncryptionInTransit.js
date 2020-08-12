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
    description: 'Ensures S3 buckets have bucket policy statements that deny insecure transport',
    more_info: 'S3 bucket policies can be configured to deny access to the bucket over HTTP.',
    recommended_action: 'Add statements to the bucket policy that deny all S3 actions when SecureTransport is false. Resources must be list of bucket ARN and bucket ARN with wildcard.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
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
                var policyJson;
                if (typeof getBucketPolicy.data.Policy === 'string') {
                    policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } else {
                    policyJson = getBucketPolicy.data.Policy;
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
                helpers.addResult(results, 2, 'Bucket does not enforce encryption in transit', 'global', bucketResource);
            }
        }
        callback(null, results, source);
    }
};
