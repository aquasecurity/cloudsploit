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
            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3, 'Unable to list guardduty detectors: ' + helpers.addError(listDetectors), region);
                return rcb();
            }

            // describe each detector
            const detectors = listDetectors.data
                .map(detectorId => {
                    const getDetector = helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);
                    if (!getDetector) return { Status: 'unknown' };
                    if (getDetector.err || !getDetector.data) {
                        helpers.addResult(results, 3, `Unable to get guardduty detector: ${helpers.addError(listDetectors)}`, region, detectorId);
                        return { Status: 'unknown' };
                    }
                    return { detectorId, ...getDetector.data};
                });

            if (!detectors.length) {
                helpers.addResult(results, 2, 'GuardDuty not enabled', region);
            } else {
                const enabledDetectors = detectors.filter(detector => detector.Status === 'ENABLED');
                const badDetectors = detectors.filter(detector => detector.Status !== 'ENABLED');
                if (enabledDetectors.length) {
                    enabledDetectors.forEach(detector => {
                        helpers.addResult(results, 0, 'GuardDuty is enabled', region, detector.detectorId);
                    });
                } else {
                    badDetectors.forEach(detector => {
                        helpers.addResult(results, 2, `GuardDuty detector is ${detector.Status}`, region, detector.detectorId);
                    });
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
