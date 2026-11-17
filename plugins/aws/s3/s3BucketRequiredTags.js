var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Required Tags',
    category: 'S3',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensures that S3 buckets have the configured required tags with proper values.',
    more_info: 'Tags make it possible to find the owner, the data classification and the backup requirements of a resource. ' +
        'The required tags, and the allowed values of each tag, are defined in the settings of this plugin. Without required tags configured, no bucket is evaluated.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html',
    recommended_action: 'Add the required tags with a proper value to the S3 bucket.',
    apis: ['S3:listBuckets', 'S3:getBucketTagging', 'S3:getBucketLocation'],
    settings: {
        s3_required_tags: {
            name: 'S3 Bucket Required Tags',
            description: 'JSON object with the required tag keys and the comma separated allowed values of each tag, ' +
                'for example {"Owner":"*","Environment":"dev,test,prod"}. An asterisk as value accepts any non-empty value. ' +
                'When empty ({}), no tags are required.',
            regex: '^\\{.*\\}$',
            default: '{}'
        },
        s3_required_tags_exempt_keys: {
            name: 'S3 Bucket Required Tags Exempt Tag Keys',
            description: 'Comma separated list of tag keys. Buckets that have one of these tag keys are not evaluated. When empty, every bucket is evaluated.',
            regex: '^[^,]*(,[^,]+)*$',
            default: ''
        }
    },
    realtime_triggers: ['s3:CreateBucket', 's3:PutBucketTagging', 's3:DeleteBucket'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var requiredTags;
        try {
            requiredTags = JSON.parse(settings.s3_required_tags || this.settings.s3_required_tags.default);
        } catch (e) {
            helpers.addResult(results, 3, 'The setting s3_required_tags is not valid JSON: ' + e.message);
            return callback(null, results, source);
        }

        var exemptKeys = (settings.s3_required_tags_exempt_keys || this.settings.s3_required_tags_exempt_keys.default)
            .split(',').map(function(key) { return key.trim(); }).filter(Boolean);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', defaultRegion]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, 'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets found');
            return callback(null, results, source);
        }

        listBuckets.data.forEach(function(bucket) {
            if (!bucket.Name) return;

            var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);
            var bucketArn = 'arn:' + awsOrGov + ':s3:::' + bucket.Name;

            // The tags are collected in the region of the bucket or in the default region
            var getBucketTagging = helpers.addSource(cache, source, ['s3', 'getBucketTagging', bucketLocation, bucket.Name]) ||
                helpers.addSource(cache, source, ['s3', 'getBucketTagging', defaultRegion, bucket.Name]);

            var tags;
            if (getBucketTagging && getBucketTagging.err && getBucketTagging.err.code === 'NoSuchTagSet') {
                tags = [];
            } else if (!getBucketTagging || getBucketTagging.err || !getBucketTagging.data) {
                helpers.addResult(results, 3,
                    'Unable to query the tags of the S3 bucket: ' + helpers.addError(getBucketTagging), bucketLocation, bucketArn);
                return;
            } else {
                tags = getBucketTagging.data.TagSet;
            }

            var tagMap = helpers.normalizeTags(tags);

            if (exemptKeys.some(function(key) { return tagMap[key] !== undefined; })) {
                helpers.addResult(results, 0, 'Resource is out of scope, it has an exempt tag', bucketLocation, bucketArn);
                return;
            }

            var evaluation = helpers.evaluateRequiredTags(tags, requiredTags);
            helpers.addResult(results, evaluation.status, evaluation.message, bucketLocation, bucketArn);
        });

        callback(null, results, source);
    }
};
