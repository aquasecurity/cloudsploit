var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Log Sinks Enabled',
    category: 'Logging',
    description: 'Ensures a log sink is enabled to export all logs',
    more_info: 'Log sinks send log data to a storage service for archival and compliance. A log sink with no filter is necessary to ensure that all logs are being properly sent. If logs are sent to a storage bucket, the bucket must exist and bucket versioning should exist.',
    link: 'https://cloud.google.com/logging/docs/export/',
    recommended_action: 'Ensure a log sink is configured properly with an empty filter and a destination.',
    apis: ['sinks:list', 'buckets:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.sinks, function(region, rcb){
            let sinks = helpers.addSource(cache, source,
                ['sinks', 'list', region]);

            if (!sinks) return rcb();

            if (sinks.err || !sinks.data) {
                helpers.addResult(results, 3, 'Unable to query sinks: ' + helpers.addError(sinks), region);
                return rcb();
            }

            if (!sinks.data.length) {
                helpers.addResult(results, 2, 'No sinks found', region);
                return rcb();
            }
            var noSinks = true;
            var bucketName ='';
            var sinkName = '';
            sinks.data.forEach(sink => {
                if ((!sink.filter ||
                    (sink.filter &&
                    sink.filter === '')) &&
                    sink.destination) {
                    var destinationType = sink.destination.split('.')[0];
                    if (destinationType === 'storage') {
                        bucketName = sink.destination.split('/')[1];
                    }
                    noSinks = false;
                    sinkName = sink.name
                }
            });
            if (bucketName.length) {
                let buckets = helpers.addSource(cache, source,
                    ['buckets', 'list', region]);

                if (!buckets || buckets.err || !buckets.data) {
                    helpers.addResult(results, 3, 'Unable to query buckets: ' + helpers.addError(buckets), region);
                } else if (!buckets.data.length) {
                    helpers.addResult(results, 2, 'No log bucket found', region);
                    rcb();
                } else {
                    var logBucket = buckets.data.find(bucket => {
                        return bucket.name === bucketName;
                    });
                    if (logBucket) {
                        helpers.addResult(results, 0, 'The log sink is properly configured', region, sinkName);
                        if (logBucket.versioning &&
                            logBucket.versioning.enabled) {
                            helpers.addResult(results, 0, 'Log bucket versioning is enabled', region, logBucket.name);
                        } else {
                            helpers.addResult(results, 2, 'Log bucket versioning is disabled', region, logBucket.name);
                        }
                    } else {
                        helpers.addResult(results, 2, `The log bucket: ${bucketName} does not exist`, region, sinkName);
                    }
                }
            } else if (noSinks) {
                helpers.addResult(results, 2, 'No log sinks are enabled', region);
            } else {
                helpers.addResult(results, 0, 'The log sink is properly configured', region, sinkName);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
