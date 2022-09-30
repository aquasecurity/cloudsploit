var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Labels Added',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensure that all Cloud Storage buckets have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/storage/docs/using-bucket-labels',
    recommended_action: 'Ensure labels are added to all storage buckets.',
    apis: ['buckets:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb){
            let buckets = helpers.addSource(cache, source,
                ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets', region, null, null, buckets.err);
                return rcb();
            }

            if (!buckets.data.length) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            buckets.data.forEach(bucket => {
                let resource = helpers.createResourceName('b', bucket.name);

                if (bucket.labels &&
                    Object.keys(bucket.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(bucket.labels).length} labels found for storage bucket`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Storage bucket does not have any labels', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
