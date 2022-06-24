var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Lifecycle Configured',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensure that Cloud Storage buckets are using lifecycle management rules to transition objects between storage classes.',
    more_info: 'Lifecycle management rules allow you to delete buckets at the end of their lifecycle and help optimize your data for storage costs.',
    link: 'https://cloud.google.com/storage/docs/managing-lifecycles',
    recommended_action: 'Modify storage buckets and configure lifecycle rules.',
    apis: ['buckets:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb) {
            let buckets = helpers.addSource(
                cache, source, ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region, null, null, buckets.err);
                return rcb();
            }

            if (!helpers.hasBuckets(buckets.data)) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            var bucketFound = false;
            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    bucketFound = true;

                    if (bucket.lifecycle && bucket.lifecycle.rule && bucket.lifecycle.rule.length) {
                        helpers.addResult(results, 0, 'Bucket has lifecycle management configured', region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Bucket does not have lifecycle management configured', region, resource);
                    }
                }
            });

            if (!bucketFound) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};