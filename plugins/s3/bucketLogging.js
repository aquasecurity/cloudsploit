var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'S3 Bucket Logging',
    category: 'S3',
    description: 'Ensures S3 bucket logging is enabled for S3 buckets',
    more_info: 'S3 bucket logging helps maintain an audit trail of \
                access that can be used in the event of a security \
                incident.',
    recommended_action: 'Enable bucket logging for each S3 bucket.',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Logging.html',
    apis: ['S3:listBuckets', 'S3:getBucketLogging'],
    compliance: {
        hipaa: 'HIPAA requires strict auditing controls around data access. ' +
                'S3 logging helps ensure these controls are met by logging ' +
                'access to all bucket objects. Logs should be stored in a ' +
                'secure, remote location.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';

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
            var getBucketLogging = helpers.addSource(cache, source,
                ['s3', 'getBucketLogging', region, bucket.Name]);

            if (!getBucketLogging || getBucketLogging.err || !getBucketLogging.data) {
                helpers.addResult(results, 3,
                    'Error querying bucket logging for : ' + bucket.Name +
                    ': ' + helpers.addError(getBucketLogging),
                    'global', 'arn:aws:s3:::' + bucket.Name)
            } else if (getBucketLogging.data.LoggingEnabled) {
                helpers.addResult(results, 0,
                    'Bucket : ' + bucket.Name + ' has logging enabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            } else {
                helpers.addResult(results, 2,
                    'Bucket : ' + bucket.Name + ' has logging disabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            }
        });
        callback(null, results, source);
    }
};