var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Logging',
    category: 'Storage',
    description: 'Ensures object logging is enabled on storage buckets',
    more_info: 'Storage bucket logging helps maintain an audit trail of access that can be used in the event of a security incident.',
    link: 'https://cloud.google.com/storage/docs/access-logs',
    recommended_action: 'Bucket Logging can only be enabled by using the Command Line Interface and the log bucket must already be created. Use this command to enable Logging: gsutil logging set on -b gs://[LOG_BUCKET_NAME] -o AccessLog \ gs://[BUCKET_NAME]',
    apis: ['buckets:list'],
    compliance: {
        hipaa: 'HIPAA requires the logging of all activity ' +
            'including access and all actions taken.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb){
            let buckets = helpers.addSource(
                cache, source, ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region);
                return rcb();
            }

            if (!buckets.data.length) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }
            buckets.data.forEach(bucket => {
                if (bucket.id) {
                    if (bucket.logging &&
                        bucket.logging.logObjectPrefix == 'AccessLog') {
                        helpers.addResult(results, 0, 'Bucket Logging Enabled', region, bucket.id);
                    } else {
                        helpers.addResult(results, 2, 'Bucket Logging not Enabled', region, bucket.id);
                    }
                } else {
                    helpers.addResult(results, 0, 'No storage buckets found', region);
                    return;
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}