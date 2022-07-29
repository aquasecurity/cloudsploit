var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Bucket Versioning',
    category: 'Object Store',
    domain: 'Storage',
    description: 'Ensures object store buckets have bucket versioning enabled.',
    more_info: 'To minimize data loss in case of inadvertent or malicious deletes, make sure that all your object store buckets are configured with object versioning.',
    recommended_action: 'Enable bucket versioning for all object store buckets.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm',
    apis: ['namespace:get', 'bucket:list', 'bucket:get'],

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
                        if (bucket.versioning &&
                            bucket.versioning === 'Enabled') {
                            helpers.addResult(results, 0,
                                `Object store bucket (${bucket.name}) has versioning enabled`, region, bucket.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Object store bucket (${bucket.name}) does not have versioning enabled`, region, bucket.id);
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