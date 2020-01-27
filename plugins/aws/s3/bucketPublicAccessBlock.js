var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Public Access Block',
    category: 'S3',
    description: 'Ensures S3 public access block is enabled on all buckets',
    more_info: 'Blocking S3 public access at the bucket-level ensures objects are not accidentally exposed.',
    recommended_action: 'Enable the S3 public access block on all S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html',
    apis: ['S3:listBuckets', 'S3:getPublicAccessBlock'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, 'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        for (let { Name: bucket } of listBuckets.data) {
            var getPublicAccessBlock = helpers.addSource(cache, source, ['s3', 'getPublicAccessBlock', region, bucket]);
            if (!getPublicAccessBlock) continue;
            if (getPublicAccessBlock.err && getPublicAccessBlock.err.code === 'NoSuchPublicAccessBlockConfiguration') {
                helpers.addResult(results, 2, 'Public Access Block not enabled', 'global', 'arn:aws:s3:::' + bucket);
                continue;
            }
            if (getPublicAccessBlock.err || !getPublicAccessBlock.data) {
                helpers.addResult(results, 3, `Error: ${helpers.addError(getPublicAccessBlock)}`, 'global', 'arn:aws:s3:::' + bucket);
                continue;
            }
            var config = getPublicAccessBlock.data.PublicAccessBlockConfiguration;
            var missingBlocks = Object.keys(config).filter(k => !config[k]);
            if (missingBlocks.length) {
                helpers.addResult(results, 2, `Missing public access blocks: ${missingBlocks.join(', ')}`, 'global', 'arn:aws:s3:::' + bucket);
                continue;
            }
            helpers.addResult(results, 0, `Public access block fully enabled`, 'global', 'arn:aws:s3:::' + bucket);
        }

        callback(null, results, source);
    }
};
