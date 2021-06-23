var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Bucket Lifecycle Configuration',
    category: 'OSS',
    description: 'Ensures that OSS buckets have lifecycle configuration enabled to automatically transition bucket objects.',
    more_info: 'Enabling lifecycle policies for OSS buckets enables automatic transition of data from one storage class to another.',
    recommended_action: 'Modify OSS buckets to enable lifecycle policies.',
    link: 'https://www.alibabacloud.com/help/doc-detail/31904.htm',
    apis: ['OSS:listBuckets', 'OSS:getBucketLifecycle', 'STS:GetCallerIdentity'],

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
        async.forEach(listBuckets.data, (bucket, cb) => {
            if (!bucket.name) return cb();

            var getBucketLifecycle = helpers.addSource(cache, source,
                ['oss', 'getBucketLifecycle', region, bucket.name]);
            
            var bucketLocation = bucket.region || region;
            bucketLocation = bucketLocation.replace('oss-', '');

            var resource = helpers.createArn('oss', accountId, 'bucket', bucket.name, bucketLocation);

            if (!getBucketLifecycle || (getBucketLifecycle.err && getBucketLifecycle.err.code && getBucketLifecycle.err.code == 'NoSuchLifecycle')) {
                helpers.addResult(results, 2,
                    'No lifecycle policy exists',
                    bucketLocation, resource);
            } else if (!getBucketLifecycle || !getBucketLifecycle.data || getBucketLifecycle.err) {
                helpers.addResult(results, 3,
                    `Unable to get OSS bucket lifecycle policy info: ${helpers.addError(getBucketLifecycle)}`, bucketLocation, resource);
                return cb();    
            } else if (getBucketLifecycle.data.Rules){
                var bucketPolicyExists = false;
                var bucketPolicyEnabled = false;
                async.forEach(getBucketLifecycle.data.Rules, (rule, rcb)=>{
                    if ('Prefix' in rule && rule.Prefix == '' ) bucketPolicyExists = true;
                    if (rule.Status && rule.Status.toLowerCase() == 'enabled' ) bucketPolicyEnabled = true;
                    return rcb();
                });
                if (bucketPolicyExists && bucketPolicyEnabled){
                    helpers.addResult(results, 0,
                        'Lifecycle policy for bucket is enabled', bucketLocation, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Lifecycle policy for bucket is not enabled', bucketLocation, resource);
                }    
            } else {
                helpers.addResult(results, 2,
                    'No lifecycle policy exists',
                    bucketLocation, resource);
            }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
