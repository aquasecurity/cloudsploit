var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Public Access Block',
    category: 'S3',
    description: 'Ensures S3 public access block is enabled on all buckets',
    more_info: 'Blocking S3 public access at the bucket-level ensures objects are not accidentally exposed.',
    recommended_action: 'Enable the S3 public access block on all S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html',
    apis: ['S3:listBuckets', 'S3:getPublicAccessBlock', 'STS:getCallerIdentity', 'S3Control:getPublicAccessBlock'],
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

        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);
        var getAccountPublicAccessBlock = helpers.addSource(cache, source, ['s3control', 'getPublicAccessBlock', region, accountId]);

        var accountAccessBlocked = false;
        var missingAccountBlocks = [];

        if (getAccountPublicAccessBlock && !getAccountPublicAccessBlock.err && getAccountPublicAccessBlock.data) {
            accountAccessBlocked = true;
            var configuration = getAccountPublicAccessBlock.data.PublicAccessBlockConfiguration;
            missingAccountBlocks = Object.keys(configuration).filter(k => !configuration[k]);
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
                if (!accountAccessBlocked && getPublicAccessBlock.err && getPublicAccessBlock.err.code === 'NoSuchPublicAccessBlockConfiguration') {
                    helpers.addResult(results, 2, 'Public Access Block not enabled', 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }

                if (getPublicAccessBlock.err || !getPublicAccessBlock.data) {
                    if (!accountAccessBlocked) {
                        helpers.addResult(results, 3, `Error: ${helpers.addError(getPublicAccessBlock)}`, 'global', 'arn:aws:s3:::' + bucket);
                        continue;
                    }
                }

                var combinedMissingBlocks = [];
                var coveredByAccount = []

                if (getPublicAccessBlock.data) {
                    var config = getPublicAccessBlock.data.PublicAccessBlockConfiguration;
                    var missingBlocks = Object.keys(config).filter(k => !config[k]);

                    missingBlocks.forEach(function(key) {
                        if (missingAccountBlocks.indexOf(key) > -1) {
                            combinedMissingBlocks.push(key);
                        } else {
                            coveredByAccount.push(key);
                        }
                    });
                }

                if (combinedMissingBlocks.length && !coveredByAccount.length) {
                    helpers.addResult(results, 2, `Missing public access blocks: ${combinedMissingBlocks.join(', ')}`, 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }

                if (combinedMissingBlocks.length && coveredByAccount.length) {
                    helpers.addResult(results, 2, `Missing public access blocks: ${combinedMissingBlocks.join(', ')}. Account level provides blocks for ${coveredByAccount.join(', ')}`, 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }

                if (!combinedMissingBlocks.length && accountAccessBlocked && coveredByAccount.length) {
                    helpers.addResult(results, 0, `Public access block fully enabled. Account level provides blocks for ${coveredByAccount.join(', ')}`, 'global', 'arn:aws:s3:::' + bucket);
                    continue;
                }

                helpers.addResult(results, 0, `Public access block fully enabled`, 'global', 'arn:aws:s3:::' + bucket);
            }
        }

        callback(null, results, source);
    }
};
