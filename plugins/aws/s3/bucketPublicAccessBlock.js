var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Public Access Block',
    category: 'S3',
    description: 'Ensures S3 public access block is enabled on all buckets',
    more_info: 'Blocking S3 public access at the bucket-level ensures objects are not accidentally exposed.',
    recommended_action: 'Enable the S3 public access block on all S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html',
    apis: ['S3:listBuckets', 'S3:getPublicAccessBlock'],
    settings: {
        s3_public_access_block_allow_pattern: {
            name: 'S3 Public Access Block Allow Pattern',
            description: 'When set, whitelists buckets matching the given pattern. Useful for overriding buckets outside the account control.',
            regex: '^.{1,255}$',
            default: false
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_public_access_block_allow_pattern: settings.s3_public_access_block_allow_pattern || this.settings.s3_public_access_block_allow_pattern.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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

        var allowRegex = (config.s3_public_access_block_allow_pattern &&
            config.s3_public_access_block_allow_pattern.length) ? new RegExp(config.s3_public_access_block_allow_pattern) : false;

        for (let { Name: bucket } of listBuckets.data) {
            var getPublicAccessBlock = helpers.addSource(cache, source, ['s3', 'getPublicAccessBlock', region, bucket]);
            if (!getPublicAccessBlock) continue;

            if (allowRegex && allowRegex.test(bucket)) {
                helpers.addResult(results, 0,
                    'Bucket: ' + bucket + ' is whitelisted via custom setting.',
                    'global', 'arn:aws:s3:::' + bucket, custom);
            } else {
                if (getPublicAccessBlock.err && getPublicAccessBlock.err.code === 'NoSuchPublicAccessBlockConfiguration') {
                    helpers.addResult(results, 2, 'Public Access Block not enabled', 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }
                if (getPublicAccessBlock.err || !getPublicAccessBlock.data) {
                    helpers.addResult(results, 3, `Error: ${helpers.addError(getPublicAccessBlock)}`, 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }
                var configLocal = getPublicAccessBlock.data.PublicAccessBlockConfiguration;
                var missingBlocks = Object.keys(configLocal).filter(k => !configLocal[k]);
                if (missingBlocks.length) {
                    helpers.addResult(results, 2, `Missing public access blocks: ${missingBlocks.join(', ')}`, 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }
                helpers.addResult(results, 0, 'Public access block fully enabled', 'global', 'arn:aws:s3:::' + bucket);
            }
        }

        callback(null, results, source);
    }
};
