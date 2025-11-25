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
    apis: ['S3:listBuckets', 'S3:getBucketTagging', 'S3:getBucketLocation'],
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

        listBuckets.data.forEach(function(bucket) {
            if (!bucket.Name) return;
            
            var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);
            var bucketArn = `arn:${awsOrGov}:s3:::${bucket.Name}`;
            
            // Try the bucket's actual region first, then fall back to default region
            var getBucketTagging = helpers.addSource(cache, source,
                ['s3', 'getBucketTagging', bucketLocation, bucket.Name]);
            
            // If not found in bucket's region, try default region (where collector runs)
            if (!getBucketTagging) {
                getBucketTagging = helpers.addSource(cache, source,
                    ['s3', 'getBucketTagging', defaultRegion, bucket.Name]);
            }
        
            
            if (!getBucketTagging || getBucketTagging.err) {
                if (getBucketTagging && getBucketTagging.err && 
                    (getBucketTagging.err.code === 'NoSuchTagSet' || 
                     getBucketTagging.err.message && getBucketTagging.err.message.includes('does not exist'))) {
                    // No tags exist for this bucket
                    helpers.addResult(results, 2, 'S3 bucket does not have any tags', bucketLocation, bucketArn);
                } else {
                    helpers.addResult(results, 3, 
                        'Unable to query S3 bucket tags: ' + helpers.addError(getBucketTagging), 
                        bucketLocation, bucketArn);
                }
                return;
            }
            
            if (getBucketTagging.data && getBucketTagging.data.TagSet && getBucketTagging.data.TagSet.length > 0) {
                helpers.addResult(results, 0, 'S3 bucket has tags', bucketLocation, bucketArn);
            } else {
                helpers.addResult(results, 2, 'S3 bucket does not have any tags', bucketLocation, bucketArn);
            }
        });
        callback(null, results, source);
    }
};
