var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket MFA Delete Status',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensures MFA delete is enabled on S3 buckets.',
    more_info: 'Adding MFA delete adds another layer of security while changing the version state' +
        'in the event of security credentials being compromised or unauthorized' +
        'access being granted.',
    recommended_action: 'Enable MFA Delete on S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html',
    apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
    compliance: {
        cis1: '2.1.3 Ensure MFA Delete is enabled on S3 buckets',
    },
    settings: {
        whitelist_buckets_for_mfa_deletion: {
            name: 'Whitelist Buckets For MFA Deletion',
            description: 'List of comma separated buckets which should be whitelisted to check',
            regex: '^.*$',
            default: '',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        
        var config = {
            whitelist_buckets_for_mfa_deletion: settings.whitelist_buckets_for_mfa_deletion || this.settings.whitelist_buckets_for_mfa_deletion.default
        };
        
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
            if (bucket.Name == helpers.CLOUDSPLOIT_EVENTS_BUCKET) return;
            
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
            
            if (config.whitelist_buckets_for_mfa_deletion.includes(bucket.Name)) {
                helpers.addResult(results, 2,
                    'Bucket : ' + bucket.Name + ' is whitelisted',
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                return;
            }

            var getBucketVersioning = helpers.addSource(cache, source,
                ['s3', 'getBucketVersioning', region, bucket.Name]);

            if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
                helpers.addResult(results, 3,
                    'Error querying bucket versioning for : ' + bucket.Name +
                    ': ' + helpers.addError(getBucketVersioning),
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
            } else if (getBucketVersioning.data.MFADelete && getBucketVersioning.data.MFADelete.toUpperCase() === 'ENABLED') {
                helpers.addResult(results, 0,
                    'Bucket : ' + bucket.Name + ' has MFA Delete enabled',
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
            } else {
                helpers.addResult(results, 2,
                    'Bucket : ' + bucket.Name + ' has MFA Delete disabled',
                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
            }
        });
        callback(null, results, source);
    }
};
