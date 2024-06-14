var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty Lambda Protection Enabled',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures GuardDuty protection is enabled for Lambda functions.' ,
    more_info: 'Enabling GuardDuty Lambda Protection helps detect potential security threats offering enhanced security by monitoring network activity logs and generating findings for suspicious activities or security issues.',
    recommended_action: 'Enable GuardDuty Lambda protection for all AWS accounts.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html',
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

                var getDetector = helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);

                if (!getDetector) return;

                if (getDetector.err || !getDetector.data) {
                    helpers.addResult(results, 3, 'Unable to get GuardDuty detector: ' + helpers.addError(getDetector),region, detectorId);
                    return;
                }

                var detector = getDetector.data;
                var resource = `arn:${awsOrGov}:guardduty:${region}:${accountId}:detector/${detector.detectorId}`;
                var lambdaLoginEventsFeature = (detector.Features && detector.Features.find(feature => feature.Name === 'LAMBDA_NETWORK_LOGS' && feature.Status === 'ENABLED')) ? true : false;

                if (lambdaLoginEventsFeature) {
                    helpers.addResult(results, 0, 'GuardDuty Lambda protection is enabled' , region, resource);
                } else {
                    helpers.addResult(results, 2, 'GuardDuty Lambda protection is disabled ' , region, resource);
                }
                 
            });
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
