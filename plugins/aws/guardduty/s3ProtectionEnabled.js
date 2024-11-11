var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 GuardDuty Enabled',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures GuardDuty is enabled for S3 buckets' ,
    more_info: 'Enabling GuardDuty S3 protection helps to detect and prevent unauthorized access to your S3 buckets.',
    recommended_action: 'Enable GuardDuty S3 protection for all AWS accounts.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:getDetector', 'STS:getCallerIdentity'],
    realtime_triggers: ['guardduty:CreateDetector', 'guardduty:UpdateDetector', 'guardduty:DeleteDetector'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var regions = helpers.regions(settings);

        async.each(regions.guardduty, function(region, rcb) {
            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);

            if (!listDetectors) return rcb();

            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3, 'Unable to list GuardDuty detectors: ' + helpers.addError(listDetectors), region);
                return rcb();
            }

            if (!listDetectors.data  ||  !listDetectors.data.length) {
                helpers.addResult(results, 0, 'No GuardDuty detectors found', region);
                return rcb();
            }

            listDetectors.data.forEach(function(detectorId) {
                var resource = `arn:${awsOrGov}:guardduty:${region}:${accountId}:detector/${detectorId}`;
                var getDetector = helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);

                if (!getDetector) return;

                if (getDetector.err || !getDetector.data) {
                    helpers.addResult(results, 3, 'Unable to get GuardDuty detector: ' + helpers.addError(getDetector),region);
                    return;
                }

                var detector = getDetector.data;

                if ( detector.DataSources  &&  detector.DataSources.S3Logs && detector.DataSources.S3Logs.Status === 'DISABLED'){
                    helpers.addResult(results, 2, 'GuardDuty S3 protection is disabled', region, resource);
                } else {
                    helpers.addResult(results, 0, 'GuardDuty S3 protection is enabled', region, resource);
                }     
            });
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
