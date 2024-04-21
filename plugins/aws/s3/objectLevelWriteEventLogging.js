var helpers = require('../../../helpers/aws');
var async = require('async');
module.exports = {
    title: 'S3 Object Write Logging',
    category: 'S3',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensure that Object-level logging for write events is enabled for S3 bucket.',
    more_info: 'Enabling Object-level S3 event logging significantly enhances security, especially for sensitive data.',
    recommended_action: 'Enable object level logging for Write events for each S3 bucket.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html#enable-cloudtrail-events.',
    apis: ['S3:listBuckets', 'CloudTrail:describeTrails', 'CloudTrail:getEventSelectors', 'S3:getBucketLocation'],
    realtime_triggers: ['s3:CreateBucket', 'cloudtrail:CreateTrail', 'cloudtrail:PutEventSelectors', 'cloudtrail:PutInsightSelectors','s3:DeleteBucket', 'cloudtrail:DeleteTrail'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
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
            helpers.addResult(results, 0, 'No S3 buckets Founds');
            return callback(null, results, source);
        }

        var isall = false;
        var buckets=[];
        var startsWithBuckets = [];
        var endsWithBuckets = [];
        var notStartsWithBuckets = [];
        var notEndsWithBuckets = [];

        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    'Unable to query for cloudtrails: ' + helpers.addError(listBuckets));
                return rcb();
            }

            describeTrails.data.forEach(event => {
                var describeEventsSelectors = helpers.addSource(cache, source,
                    ['cloudtrail', 'getEventSelectors', region, event.TrailARN]);

                if (!describeEventsSelectors || describeEventsSelectors.err || !describeEventsSelectors.data ) {
                    return;
                }
             
                if (describeEventsSelectors.data.EventSelectors) {
                    const basicEventSelectors = describeEventsSelectors.data.EventSelectors;

                    for (const event of basicEventSelectors) {
                        const dataResources = event.DataResources || [];

                        for (const dataResource of dataResources) {

                            if (dataResource.Type === 'AWS::S3::Object') {
                                if (event.ReadWriteType === 'All' || event.ReadWriteType === 'WriteOnly') {
                                    if (dataResource.Values.includes(`arn:${awsOrGov}:s3`)) {
                                        isall = true;
                                    } else {
                                        buckets = dataResource.Values.map((value) => value.split(':::')[1]);
                                        buckets = buckets.map((name) => name.slice(0, -1));
                                    } 
                                }
                            }
                        }
                    }
                } else if (describeEventsSelectors.data.AdvancedEventSelectors) {
                    var eventSelectors = describeEventsSelectors.data.AdvancedEventSelectors;

                    for (const selector of eventSelectors) {
                        
                        const fieldSelectors = selector.FieldSelectors || [];
                        const dataEventCategoryField = fieldSelectors.find((f) => f.Field === 'eventCategory' && f.Equals.includes('Data'));
                        const s3ObjectField = fieldSelectors.find((f) => f.Field === 'resources.type' && f.Equals.includes('AWS::S3::Object'));
                        const readOnlyField = fieldSelectors.find((f) => f.Field === 'readOnly' && f.Equals.includes('true'));
                        const writeOnlyField = fieldSelectors.find((f) => f.Field === 'readOnly' && f.Equals.includes('false'));
                        const resourcesARNField = fieldSelectors.find((f) => f.Field === 'resources.ARN');

                        if (dataEventCategoryField && s3ObjectField) {
                            if ((writeOnlyField || !readOnlyField )&& !resourcesARNField) {
                                isall = true; 
                            } else if (writeOnlyField ) {
                                helpers.processFieldSelectors(fieldSelectors, buckets ,startsWithBuckets,notEndsWithBuckets,endsWithBuckets, notStartsWithBuckets);
                            }
                        }
                    }    
                }
            });
            rcb();
           
        },function(){
            listBuckets.data.forEach(function(bucket){

                var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);
                const conditions = helpers.checkConditions(startsWithBuckets, notStartsWithBuckets, endsWithBuckets, notEndsWithBuckets, bucket.Name);

                if (isall || conditions.startsWithCondition || conditions.notStartsWithCondition || conditions.endsWithCondition || conditions.notEndsWithCondition){
                    helpers.addResult(results, 0, 'Bucket has object-level logging for write events', bucketLocation, `arn:${awsOrGov}:s3:::` + bucket.Name);
                } else if (buckets.length) {
                    if (buckets.includes(bucket.Name)){
                        helpers.addResult(results, 0, 'Bucket has object-level logging for write events', bucketLocation, `arn:${awsOrGov}:s3:::` + bucket.Name);
                    } else {
                        helpers.addResult(results, 2, 'Bucket does not has object-level logging for write events', bucketLocation, `arn:${awsOrGov}:s3:::` + bucket.Name);
                    }
                } else if (!isall) {
                    helpers.addResult(results, 2, 'Bucket does not has object-level logging for write events', bucketLocation, `arn:${awsOrGov}:s3:::` + bucket.Name);
                }
            });

            callback(null, results, source);
        });
    }
};
