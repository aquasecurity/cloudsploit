var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Has Tags',
    category: 'S3',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensure that AWS S3 Bucket have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify S3 buckets and add tags.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html',
    apis: ['S3:listBuckets', 'ResourceGroupsTaggingAPI:getResources', 'S3:getBucketLocation'],
    realtime_triggers: ['s3:CreateBucket', 's3:PutBucketTagging','s3:DeleteBucket'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', defaultRegion]);
        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets found');
            return callback(null, results, source);
        }

        var bucketsByRegion= {};
        listBuckets.data.forEach(function(bucket) {
            if (!bucket.Name) return;
            var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);
            if (!bucketsByRegion[bucketLocation]) {
                bucketsByRegion[bucketLocation] = [];
            }
            bucketsByRegion[bucketLocation].push(`arn:${awsOrGov}:s3:::${bucket.Name}`);
        });

        for (var region in bucketsByRegion) {
            var bucketNames = bucketsByRegion[region] || [];
            helpers.checkTags(cache, 'S3 bucket', bucketNames, region, results, settings);
        }
        callback(null, results, source);
    }
};
