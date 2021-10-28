var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'OSS Bucket Secure Transport Enabled',
    category: 'OSS',
    description: 'Ensure that Alibaba OSS buckets have secure transport enabled.',
    more_info: 'Configuring secure transfer enhances the security of OSS bucket by allowing requests to the storage account by only a secure connection.',
    recommended_action: 'Modify OSS bucket policy to configure secure transport',
    link: 'https://www.alibabacloud.com/help/doc-detail/85111.htm',
    apis: ['OSS:listBuckets', 'OSS:getBucketPolicy', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var listBuckets = helpers.addSource(cache, source, ['oss', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for OSS buckets: ${helpers.addError(listBuckets)}`, region);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No OSS buckets found', region);
            return callback(null, results, source);
        }

        listBuckets.data.forEach( bucket => {
            if (!bucket.name) return;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['oss', 'getBucketPolicy', region, bucket.name]);
            var bucketLocation = bucket.region || region;
            bucketLocation = bucketLocation.replace('oss-', '');

            var resource = helpers.createArn('oss', accountId, 'bucket', bucket.name, bucketLocation);

            if (getBucketPolicy && getBucketPolicy.data && getBucketPolicy.data.status == 404) {
                helpers.addResult(results, 2,
                    'No OSS bucket policy found', bucketLocation, resource);
                return;
            }
            
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data) {
                helpers.addResult(results, 3,
                    `Unable to query OSS bucket policy: ${helpers.addError(getBucketPolicy)}`, bucketLocation, resource);
                return;
            }

            let statements = helpers.normalizePolicyDocument(getBucketPolicy.data);

            let secureTransportEnabled = false;
            for (let statement of statements) {
                if (statement.Principal && statement.Principal.includes('*') &&
                    statement.Action && statement.Action.length &&
                    statement.Condition && statement.Condition.Bool) {
                    let conditionValue = statement.Condition.Bool[Object.keys(statement.Condition.Bool).find(key => key.toLowerCase() == 'acs:securetransport')];
                    if (statement.Effect && statement.Effect.toUpperCase() == 'DENY' &&
                        conditionValue.find(boolValue => boolValue.toLowerCase() == 'false')) {
                        secureTransportEnabled = true;
                        break;
                    } else if (conditionValue.find(boolValue => boolValue.toLowerCase() == 'true')) {
                        secureTransportEnabled = true;
                        break;
                    }
                }
            }

            if (secureTransportEnabled) {
                helpers.addResult(results, 0, 'OSS bucket has secure transport enabled', region, resource);
            } else {
                helpers.addResult(results, 2, 'OSS bucket does not have secure transport enabled', region, resource);
            }
        });

        callback(null, results, source);
    }
};
