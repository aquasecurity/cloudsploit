var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Secure Transport Enabled',
    category: 'S3',
    description: 'Ensure AWS S3 buckets enforce SSL to secure data in transit',
    more_info: 'S3 buckets should be configured to strictly require SSL connections ' +
               'to deny unencrypted HTTP requests when dealing with sensitive data.',
    recommended_action: 'Update S3 bucket policy to enforse SSL to secure data in transit.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets found');
            return callback(null, results, source);
        }

        listBuckets.data.forEach(bucket => {
            if (!bucket.Name) return;

            var resource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err &&
                getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2, 'No bucket policy found', 'global', resource);
            }
            else if (!getBucketPolicy || getBucketPolicy.err ||
                       !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    `Error querying for bucket policy for bucket "${bucket.Name}" ${helpers.addError(getBucketPolicy)}`,
                    'global', resource);
            }
            else {
                var policyJson;

                if (typeof getBucketPolicy.data.Policy == 'object') {
                    policyJson = getBucketPolicy.data.Policy;

                } else {
                    try {
                        policyJson = JSON.parse(getBucketPolicy.data.Policy);
                    }
                    catch(e) {
                        helpers.addResult(results, 3,
                            `Error querying for bucket policy for bucket: "${bucket.Name}". Policy JSON could not be parsed`,
                            'global', resource);
                        return;
                    }
                }

                if (!policyJson || !policyJson.Statement) {
                    helpers.addResult(results, 3,
                        `Error querying for bucket policy for bucket: "${bucket.Name}". Policy JSON is invalid or does not contain valid statements.`,
                        'global', resource);
                }
                else if (!policyJson.Statement.length) {
                    helpers.addResult(results, 2,
                        'Bucket policy does not contain any statements',
                        'global', resource);
                } else {
                    var sslEnforced = false;
                    for (var s in policyJson.Statement) {
                        var statement = policyJson.Statement[s];
                        if (statement.Effect &&
                            statement.Condition &&
                            statement.Condition.Bool &&
                            statement.Condition.Bool['aws:SecureTransport']) {
                            var secureTransport = statement.Condition.Bool['aws:SecureTransport'];
                            var statementEffect = statement.Effect;

                            if (secureTransport === 'false' && statementEffect === 'Deny') {
                                sslEnforced = true;
                            }
                        }
                    }

                    if(sslEnforced){
                        helpers.addResult(results, 0,
                            `Bucket Policy for bucket "${bucket.Name}" enforces SSL to secure data in transit`,
                            'global', resource);
                    }
                    else {
                        helpers.addResult(results, 2,
                            `Bucket Policy for bucket "${bucket.Name}" does not enforce SSL to secure data in transit`,
                            'global', resource);
                    }
                }
            }
        });

        callback(null, results, source);
    }
};