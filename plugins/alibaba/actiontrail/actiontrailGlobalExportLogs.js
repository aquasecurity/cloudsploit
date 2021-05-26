var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'ActionTrail Global Export Logs',
    category: 'ActionTrail',
    description: 'Ensure that ActionTrail is configured to export copies of all log entries for all regions.',
    more_info: 'ActionTrail records API calls for Alibaba account which can be exported to OSS bucket. There should be at least one trail which logs all API calls for all regions.',
    link: 'https://www.alibabacloud.com/help/doc-detail/28810.htm',
    recommended_action: 'Create an ActionTrail trail with applied regions set to All Regions and event type set to All',
    apis: ['ActionTrail:DescribeTrails'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var globalTrailFound = false;
        var globalTrailOSS = false;
        async.each(regions.actiontrail, function(region, rcb) {
            var describeTrails = helpers.addSource(cache, source, ['actiontrail', 'DescribeTrails', region]);
            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3, 'Unable to query ActionTrail trails: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            async.each(describeTrails.data, (trail, tcb) => {
                if (!trail.Name) return tcb();

                if (trail.TrailRegion && trail.TrailRegion.toLowerCase() == 'all' &&
                    trail.EventRW && trail.EventRW.toLowerCase() == 'all') {
                    globalTrailFound = true;

                    if (trail.OssBucketName && trail.OssBucketName.length) {
                        globalTrailOSS = true;
                    }
                }

                tcb();
            }, function() {
                rcb();
            });
        }, function(){
            if (globalTrailFound && globalTrailOSS) {
                helpers.addResult(results, 0,
                    'ActionTrail has a global trail to log all events', 'global');
            } else if (globalTrailFound){
                helpers.addResult(results, 2,
                    'ActionTrail has global trail to log all events but does not export logs to OSS bucket', 'global');
            } else {
                helpers.addResult(results, 2,
                    'ActionTrail does not have global trail to log all events', 'global');
            }
            callback(null, results, source);
        });
    }
};
