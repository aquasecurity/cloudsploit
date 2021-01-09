var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Transfer Acceleration Enabled',
    category: 'S3',
    description: 'Ensures that S3 buckets have transfer acceleration enabled to increase the speed of data transfers.',
    more_info: 'S3 bucket should have transfer acceleration enabled to increase the speed of data transfers.',
    recommended_action: 'Update S3 bucket permissions and enable Transfer Acceleration.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html',
    apis: ['S3:listBuckets', 'S3:getBucketAccelerateConfiguration'],

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

        listBuckets.data.forEach(function(bucket){
            var resource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketAccelerateConfiguration = helpers.addSource(cache, source,
                ['s3', 'getBucketAccelerateConfiguration', region, bucket.Name]);

            if (!getBucketAccelerateConfiguration || getBucketAccelerateConfiguration.err || !getBucketAccelerateConfiguration.data) {
                helpers.addResult(results, 3,
                    `Unable to get bucket acceleration configuration: ${helpers.addError(getBucketAccelerateConfiguration)}`,
                    region, resource);
                    return;
            }

            if (getBucketAccelerateConfiguration.data.Status && getBucketAccelerateConfiguration.data.Status.toUpperCase() === 'ENABLED') {
                helpers.addResult(results, 0,
                    `S3 bucket ${bucket.Name} has transfer acceleration enabled`,
                    region, resource);
            } else {
                helpers.addResult(results, 2,
                    `S3 bucket ${bucket.Name} does not have transfer acceleration enabled`,
                    region, resource);
            }
        });

        callback(null, results, source);
    },
};