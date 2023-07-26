var helpers = require('../../../helpers/aws');
var async = require('async');
module.exports = {
    title: 'S3 Object Read Logging',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensure that Object-level logging for read events is enabled for S3 bucket',
    more_info: 'Enabling Object-level S3 event logging significantly enhances security, especially for sensitive data.',
    recommended_action: 'Enable object level logging for read events for each S3 bucket.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html#enable-cloudtrail-events.',
    apis: ['S3:listBuckets', 'CloudTrail:describeTrails', 'CloudTrail:getEventSelectors', 'S3:getBucketLocation'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
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
        var Buckets=[];
        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);
            if (!describeTrails) return rcb();
            if (describeTrails.err || !describeTrails.data) {
                return rcb();
            }
            if (!describeTrails.data.length) {
                return rcb();
            }
            describeTrails.data.forEach(event => {
                var resource = event.TrailARN;
                var describeEventsSelectors = helpers.addSource(cache, source,
                    ['cloudtrail', 'getEventSelectors', region, resource]);
                if (!describeEventsSelectors) return;
                if (describeEventsSelectors.err || !describeEventsSelectors.data ) {
                    return;
                }
             
                if (describeEventsSelectors.data.EventSelectors) {
                    const basicEventSelectors = describeEventsSelectors.data.EventSelectors;
                    for (const event of basicEventSelectors) {
                        const dataResources = event.DataResources || [];
                        for (const dataResource of dataResources) {
                            if (dataResource.Type === 'AWS::S3::Object') {
                                if (event.ReadWriteType === 'All' || event.ReadWriteType === 'ReadOnly') {
                                    if (dataResource.Values.includes('arn:aws:s3')) {
                                        isall = true;
                                    } else {
                                        Buckets = dataResource.Values.map((value) => value.split(':::')[1]);
                                        Buckets = Buckets.map((name) => name.slice(0, -1));
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
                            if ((readOnlyField || !writeOnlyField )&& !resourcesARNField) {
                                isall = true; 
                            } else {
                                Buckets = fieldSelectors
                                    .filter((f) => f.Field === 'resources.ARN')
                                    .map((f) => f.Equals[0].split(':::')[1]);
                                Buckets = Buckets.map((name) => name.slice(0, -1));
                            }
                        }
                    }    
                }
            });
            rcb();
           
        },function(){
            listBuckets.data.forEach(function(bucket){
                var bucketLocation = helpers.getS3BucketLocation(cache, defaultRegion, bucket.Name);
                if (isall) {
                    helpers.addResult(results, 0, 'Bucket has object-level logging for read events', bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                } else if (Buckets.length) {
                    if (Buckets.includes(bucket.Name)){
                        helpers.addResult(results, 0, 'Bucket has object-level logging for read events', bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                    } else {
                        helpers.addResult(results, 2, 'Bucket does not has object-level logging for read events', bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                    }
                } else if (!isall) {
                    helpers.addResult(results, 2, 'Bucket does not has object-level logging for read events', bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                }
            });
            callback(null, results, source);
        });
    }
};