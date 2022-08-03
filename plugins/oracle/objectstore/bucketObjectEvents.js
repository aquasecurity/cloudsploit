var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Bucket Object Events',
    category: 'Object Store',
    domain: 'Storage',
    description: 'Ensures object store buckets can emit object events.',
    more_info: 'Object store buckets should be configured to emit object events in order to help monitor and keep track of bucket state changes.',
    recommended_action: 'Ensure all object store buckets are allowed to emit object events.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/managingbuckets.htm',
    apis: ['namespace:get','bucket:list', 'bucket:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bucket, function(region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var getBucket = helpers.addSource(cache, source,
                    ['bucket', 'get', region]);

                if (!getBucket) return rcb();

                if (getBucket.err || !getBucket.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for object store bucket details: ' + helpers.addError(getBucket), region);
                } else if (!getBucket.data.length) {
                    helpers.addResult(results, 0, 'No object store bucket details to check', region);
                } else {

                    getBucket.data.forEach(function(bucket) {
                        if (bucket.objectEventsEnabled) {
                            helpers.addResult(results, 0,
                                `Object store bucket (${bucket.name}) can emit object events.`, region, bucket.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Object store bucket (${bucket.name}) cannot emit object events.`, region, bucket.id);
                        }
                    });
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};