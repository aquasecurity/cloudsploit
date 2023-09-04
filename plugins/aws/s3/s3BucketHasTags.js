var helpers = require('../../../helpers/aws');
var async = require('async');

module.exports = {
    title: 'S3 Bucket Has Tags',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensure that AWS S3 Bucket have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify S3 buckets and add tags.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html',
    apis: ['S3:listBuckets', 'ResourceGroupsTaggingAPI:getResources', 'S3:getBucketLocation'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var resourceArns = [];

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

        async.each(regions.resourcegroupstaggingapi, function(region, rcb) {
            const resourceTags = helpers.addSource(cache, {},
                ['resourcegroupstaggingapi', 'getResources', region]);

            if (!resourceTags) return rcb();

            if (resourceTags.err ) {
                helpers.addResult(results , 3, 'Unable to query for Resource Group Tagging',region, helpers.addError(resourceTags));
                return rcb();
            }
            if (!resourceTags.data || !resourceTags.data.length) return rcb();

            resourceArns.push(...resourceTags.data.filter(data => data.Tags && data.Tags.length).map(data => data.ResourceARN));

            rcb();
        }, function() {
            for (let bucket of listBuckets.data) {
                const arn = `arn:${awsOrGov}:s3:::${bucket.Name}`;
                var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);

                if (resourceArns.includes(arn)) {
                    helpers.addResult(results, 0, 'S3 bucket has tags', bucketLocation, arn);
                } else {
                    helpers.addResult(results, 2, 'S3 bucket does not have any tags', bucketLocation, arn);
                }
            }
            callback(null, results, source);
        });
    }
};
