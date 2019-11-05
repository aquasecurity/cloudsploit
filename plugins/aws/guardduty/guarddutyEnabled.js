var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty is Enabled',
    category: 'GuardDuty',
    description: 'Ensures GuardDuty is enabled',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:getDetector'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.guardduty, function(region, rcb) {
            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
            if (!listDetectors) return rcb();
            if (listDetectors.err) {
                helpers.addResult(results, 3, 'Unable to query GuardDuty', region);
            } else if (!listDetectors.data.length) {
                helpers.addResult(results, 2, 'GuardDuty not enabled', region);
            } else {
                helpers.addResult(results, 0, 'GuardDuty is enabled', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
