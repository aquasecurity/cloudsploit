var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Log Sinks Enabled',
    category: 'Logging',
    description: 'Ensures a log sink is enabled to export all logs',
    more_info: 'Log sinks send log data to a storage service for archival and compliance. A log sink with no filter is necessary to ensure that all logs are being properly sent. If logs are sent to a storage bucket, the bucket must exist and bucket versioning should exist.',
    link: 'https://cloud.google.com/logging/docs/export/',
    recommended_action: 'Ensure a log sink is configured properly with an empty filter and a destination.',
    apis: ['sinks:list', 'buckets:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.sinks, function(region, rcb){
            let sinks = helpers.addSource(cache, source,
                ['sinks', 'list', region]);

            if (!sinks) return rcb();

            if (sinks.err || !sinks.data) {
                helpers.addResult(results, 3, 'Unable to query sinks: ' + helpers.addError(sinks), region, null, null, sinks.err);
                return rcb();
            }

            if (!sinks.data.length) {
                helpers.addResult(results, 2, 'No sinks found', region);
                return rcb();
            }
            var noSinks = true;
            var bucketName ='';
            var sinkName = '';
            var sinkResource;
            sinks.data.forEach(sink => {
                if ((!sink.filter || (sink.filter && sink.filter === '')) && sink.destination) {
                    var destinationType = sink.destination.split('.')[0];
                    if (destinationType === 'storage') {
                        bucketName = sink.destination.split('/')[1];
                    }
                    noSinks = false;
                    sinkName = sink.name;
                    sinkResource = helpers.createResourceName('sinks', sinkName, project);
                }
            });
            if (bucketName.length) {
                let buckets = helpers.addSource(cache, source,
                    ['buckets', 'list', region]);

                if (!buckets || buckets.err || !buckets.data) {
                    helpers.addResult(results, 3, 'Unable to query buckets: ' + helpers.addError(buckets), region, null, null, buckets.err);
                } else if (!buckets.data.length) {
                    helpers.addResult(results, 2, 'No log bucket found', region);
                    rcb();
                } else {
                    var logBucket = buckets.data.find(bucket => {
                        return bucket.name === bucketName;
                    });
                    if (logBucket) {
                        let bucketResource = helpers.createResourceName('b', logBucket.name);
                        helpers.addResult(results, 0, 'The log sink is properly configured', region, sinkResource);
                        if (logBucket.versioning &&
                            logBucket.versioning.enabled) {
                            helpers.addResult(results, 0, 'Log bucket versioning is enabled', region, bucketResource);
                        } else {
                            helpers.addResult(results, 2, 'Log bucket versioning is disabled', region, bucketResource);
                        }
                    } else {
                        helpers.addResult(results, 2, `The log bucket: ${bucketName} does not exist`, region, sinkResource);
                    }
                }
            } else if (noSinks) {
                helpers.addResult(results, 2, 'No log sinks are enabled', region);
            } else {
                helpers.addResult(results, 0, 'The log sink is properly configured', region, sinkResource);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
