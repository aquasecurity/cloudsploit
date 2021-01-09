var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Lifecycle Configuration',
    category: 'S3',
    description: 'Ensures that S3 buckets have lifecycle configuration enabled to automatically transition S3 bucket objects.',
    more_info: 'S3 bucket should have lifecycle configuration enabled to automatically transition S3 bucket objects to Infrequent Access.',
    recommended_action: 'Update S3 bucket and create lifecycle rule configuration',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-set-lifecycle-configuration-intro.html',
    apis: ['S3:listBuckets', 'S3:getBucketLifecycleConfiguration'],

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

        async.each(listBuckets.data, function(bucket, cb){
            var resource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketLifecycleConfiguration = helpers.addSource(cache, source,
                ['s3', 'getBucketLifecycleConfiguration', region, bucket.Name]);

            if (getBucketLifecycleConfiguration && getBucketLifecycleConfiguration.err &&
                getBucketLifecycleConfiguration.err.code && getBucketLifecycleConfiguration.err.code == 'NoSuchLifecycleConfiguration') {
                helpers.addResult(results, 2,
                    `S3 bucket ${bucket.Name} has lifecycle configuration disabled`,
                    region, resource);
            } else if (!getBucketLifecycleConfiguration || getBucketLifecycleConfiguration.err || !getBucketLifecycleConfiguration.data) {
                helpers.addResult(results, 3,
                    `Unable to query for S3 bucket lifecycle configuration: ${helpers.addError(getBucketLifecycleConfiguration)}`,
                    region, resource);
            } else if (getBucketLifecycleConfiguration.data &&
                getBucketLifecycleConfiguration.data.Rules &&
                getBucketLifecycleConfiguration.data.Rules[0] &&
                getBucketLifecycleConfiguration.data.Rules[0].Status &&
                getBucketLifecycleConfiguration.data.Rules[0].Status.toUpperCase() === 'ENABLED') {
                helpers.addResult(results, 0,
                    `S3 bucket ${bucket.Name} has lifecycle configuration enabled`,
                    region, resource);
            } else {
                helpers.addResult(results, 2,
                    `S3 bucket ${bucket.Name} has lifecycle configuration disabled`,
                    region, resource);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};