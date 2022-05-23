var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Versioned Buckets Lifecycle Configuration',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensure that S3 buckets having versioning enabled also have liecycle policy configured for non-current objects.',
    more_info: 'When object versioning is enabled on a bucket, every modification/update to an object results in a new version of the object that will be stored indefinitely. ' +
        'Enable a lifecycle policy, so that non-current object versions are removed or transitioned in a predictable manner.',
    recommended_action: 'Configure lifecycle rules for buckets which have versioning enabled',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-set-lifecycle-configuration-intro.html',
    apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation', 'S3:getBucketLifecycleConfiguration'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
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

        var nonCurrentVersionRules = [
            'NoncurrentVersionTransitions',
            'NoncurrentVersionExpiration'
        ];

        listBuckets.data.forEach(function(bucket){
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

            var getBucketVersioning = helpers.addSource(cache, source,
                ['s3', 'getBucketVersioning', region, bucket.Name]);

            if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
                helpers.addResult(results, 3,
                    'Error querying bucket versioning for : ' + bucket.Name +
                    ': ' + helpers.addError(getBucketVersioning),
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
            } else if (getBucketVersioning.data.Status == 'Enabled') {
                var getBucketLifecycleConfiguration = helpers.addSource(cache, source,
                    ['s3', 'getBucketLifecycleConfiguration', region, bucket.Name]);
    
                if (getBucketLifecycleConfiguration && getBucketLifecycleConfiguration.err &&
                    getBucketLifecycleConfiguration.err.code && getBucketLifecycleConfiguration.err.code == 'NoSuchLifecycleConfiguration') {
                    helpers.addResult(results, 2,
                        `S3 bucket ${bucket.Name} has versioning enabled but has lifecycle configuration disabled`,
                        bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                } else if (!getBucketLifecycleConfiguration || getBucketLifecycleConfiguration.err || !getBucketLifecycleConfiguration.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for S3 bucket lifecycle configuration: ${helpers.addError(getBucketLifecycleConfiguration)}`,
                        bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                } else if (getBucketLifecycleConfiguration.data.Rules &&
                    getBucketLifecycleConfiguration.data.Rules.length) {
                    var ruleExists = getBucketLifecycleConfiguration.data.Rules.find(rule => rule.Status && rule.Status.toUpperCase() === 'ENABLED');

                    if (ruleExists) {
                        var ruleForNonCurrent = getBucketLifecycleConfiguration.data.Rules.find(rule => rule.Status &&
                                rule.Status.toUpperCase() === 'ENABLED' &&
                                Object.keys(rule).some(key => nonCurrentVersionRules.includes(key) && rule[key].length));
                        if (ruleForNonCurrent) {
                            helpers.addResult(results, 0,
                                `S3 bucket ${bucket.Name} has versioning and lifecycle configuration enabled for non-current versions`,
                                bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                        } else {
                            helpers.addResult(results, 2,
                                `S3 bucket ${bucket.Name} has versioning and lifecycle configuration enabled but lifecycle policy includes no rule for non-current objects`,
                                bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            `S3 bucket ${bucket.Name} has versioning and lifecycle configuration configured but lifecycle policy does not have enabled rules`,
                            bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `S3 bucket ${bucket.Name} has versioning enabled but has lifecycle configuration disabled`,
                        bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                }
            } else {
                helpers.addResult(results, 0,
                    'Bucket : ' + bucket.Name + ' has versioning disabled',
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
            }
        });

        callback(null, results, source);
    }
};