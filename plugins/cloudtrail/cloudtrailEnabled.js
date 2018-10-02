var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'CloudTrail Enabled',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail is enabled for all regions within an account',
    more_info: 'CloudTrail should be enabled for all regions in order to detect suspicious activity in regions that are not typically used.',
    recommended_action: 'Enable CloudTrail for all regions and ensure that at least one region monitors global service events',
    link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:getTrailStatus'],
    compliance: {
        hipaa: 'HIPAA has clearly defined audit requirements for environments ' +
        'containing sensitive data. CloudTrail is the recommended ' +
        'logging and auditing solution for AWS since it is tightly ' +
        'integrated into most AWS services and APIs.'
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        var globalServicesMonitored = false;

        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudTrail policy: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
            } else {
                // Ensure logging is enabled
                var found;
                var globalEnabled = false;

                for (t in describeTrails.data) {
                    var trail = describeTrails.data[t];

                    if (trail.IncludeGlobalServiceEvents) {
                        globalServicesMonitored = true;
                        globalEnabled = true;
                    }

                    var getTrailStatus = helpers.addSource(cache, source,
                        ['cloudtrail', 'getTrailStatus', region, trail.TrailARN]);

                    if (getTrailStatus && getTrailStatus.data &&
                        getTrailStatus.data.IsLogging) {

                        helpers.addResult(results, 0, 'CloudTrail is enabled', region);

                        if (trail.IncludeGlobalServiceEvents) {
                            helpers.addResult(results, 0, 'CloudTrail is enabled to monitor global services', region);
                        }

                        found = true;
                        break;
                    }
                }

                if (!found) {
                    helpers.addResult(results, 2, 'CloudTrail is setup but is not logging API calls', region);
                    if (globalEnabled){
                        helpers.addResult(results, 2, 'CloudTrail is configured for Global Monitoring in the ' + region + ' region but is not logging API calls');
                    }
                }
            }

            rcb();
        }, function(){
            if (!globalServicesMonitored) {
                helpers.addResult(results, 2, 'CloudTrail is not configured to monitor global services');
            } else {
                helpers.addResult(results, 0, 'CloudTrail is configured to monitor global services');
            }

            callback(null, results, source);
        });
    }
};