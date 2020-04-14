var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Account Public Access Block',
    category: 'S3',
    description: 'Ensures S3 public access block is enabled on an account level',
    more_info: 'Blocking S3 public access at the account level ensures objects are not accidentally exposed.',
    recommended_action: 'Enable the S3 public access block on the account.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html',
    apis: ['STS:getCallerIdentity', 'S3Control:getPublicAccessBlock'],
    settings: {
        s3_public_access_block_on_account: {
            name: 'S3 Public Access Block On Account',
            description: 'When set, checks to see if public access block is enabled at the account level',
            default: false
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_public_access_block_on_account: settings.s3_public_access_block_on_account || this.settings.s3_public_access_block_on_account.default
        };

        if (config.s3_public_access_block_on_account) {
            var results = [];
            var source = {};
            var region = helpers.defaultRegion(settings);

            var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);

            if (!accountId) return callback(null, results, source);

            var getAccountPublicAccessBlock = helpers.addSource(cache, source, ['s3control', 'getPublicAccessBlock', region, accountId]);
    
            if (!getAccountPublicAccessBlock) return callback(null, results, source);

            if (getAccountPublicAccessBlock.err && getAccountPublicAccessBlock.err.code === 'NoSuchPublicAccessBlockConfiguration') {
                helpers.addResult(results, 2, 'Public Access Block not enabled', accountId);
                return callback(null, results, source);
            }

            if (getAccountPublicAccessBlock.err || !getAccountPublicAccessBlock.data) {
                helpers.addResult(results, 3, 'Unable to query for ' + helpers.addError(getAccountPublicAccessBlock));
                return callback(null, results, source);
            }

            var configuration = getAccountPublicAccessBlock.data.PublicAccessBlockConfiguration;         
            var missingAccountBlocks = Object.keys(configuration).filter(k => !configuration[k]);
    
            if (missingAccountBlocks.length) {
                helpers.addResult(results, 2, `Missing public access blocks: ${missingAccountBlocks.join(', ')}`, accountId);
                return callback(null, results, source);
            }
            
            helpers.addResult(results, 0, "Public Access Block Is Enabled On This Account", accountId)
    
            callback(null, results, source);
        } else {
            callback();
        }
        
    }
};
