var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Versioning',
    category: 'S3',
    description: 'Ensures object versioning is enabled on S3 buckets',
    more_info: 'Object versioning can help protect against the overwriting of \
                objects or data loss in the event of a compromise.',
    recommended_action: 'Enable object versioning for buckets with \
                        sensitive contents at a minimum and for all buckets \
                        ideally.',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html',
    apis: ['S3:listBuckets', 'S3:getBucketVersioning'],

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

        listBuckets.data.forEach(function(bucket){
            var getBucketVersioning = helpers.addSource(cache, source,
                ['s3', 'getBucketVersioning', region, bucket.Name]);

            if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
                helpers.addResult(results, 3,
                    'Error querying bucket versioning for : ' + bucket.Name +
                    ': ' + helpers.addError(getBucketVersioning),
                    'global', 'arn:aws:s3:::' + bucket.Name);
            } else if (getBucketVersioning.data.Status == 'Enabled') {
                helpers.addResult(results, 0,
                    'Bucket : ' + bucket.Name + ' has versioning enabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            } else {
                helpers.addResult(results, 2,
                    'Bucket : ' + bucket.Name + ' has versioning disabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            }
        });

        callback(null, results, source);
    }
};