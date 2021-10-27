var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'OSS Bucket IP Restriction Configured',
    category: 'OSS',
    description: 'Ensure that OSS buckets have policy configured to allow only specific IP addresses.',
    more_info: 'OSS buckets should limit access to selected networks. Restricting default network access provides a new layer of security.',
    recommended_action: 'Add or modify bucket policy to create IP-based conditions',
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

            let ipRestrictionInPlace = false;
            for (let statement of statements) {
                if (statement.Principal && statement.Action && statement.Condition) {
                    if (statement.Condition.IpAddress) {
                        let conditionValue = statement.Condition.IpAddress[Object.keys(statement.Condition.IpAddress).find(key => key.toLowerCase() == 'acs:sourceip')];
                        if (conditionValue.length) {
                            ipRestrictionInPlace = true;
                            break;
                        }
                    } else if (statement.Condition.NotIpAddress) {
                        let conditionValue = statement.Condition.NotIpAddress[Object.keys(statement.Condition.NotIpAddress).find(key => key.toLowerCase() == 'acs:sourceip')];
                        if (conditionValue.length) {
                            ipRestrictionInPlace = true;
                            break;
                        }
                    }
                }
            }

            if (ipRestrictionInPlace) {
                helpers.addResult(results, 0,
                    'OSS bucket has IP restrictions configured', region, resource);
            } else {
                helpers.addResult(results, 2,
                    'OSS bucket does not have IP restrictions configured', region, resource);
            }
        });

        callback(null, results, source);
    }
};
