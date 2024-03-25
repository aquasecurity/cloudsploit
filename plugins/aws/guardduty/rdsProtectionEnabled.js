var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty RDS Protection Enabled',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures GuardDuty protection is enabled for RDS instances.' ,
    more_info: 'GuardDuty RDS Protection analyzes RDS login activity to identify access threats, offering enhanced security without additional infrastructure. It enables proactive threat detection, automated alerting, and flexible configuration for AWS accounts.',
    recommended_action: 'Enable GuardDuty RDS protection for all AWS accounts.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/rds-protection.html?icmpid=docs_gd_help_panel',
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
                    helpers.addResult(results, 3, 'Unable to get GuardDuty detector: ' + helpers.addError(getDetector),region);
                    return;
                }

                var detector = getDetector.data;
                var resource = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detector.detectorId;
                var rdsLoginEventsFeature = detector.Features.find(feature => feature.Name === 'RDS_LOGIN_EVENTS');

                if (rdsLoginEventsFeature) {
                    var status = rdsLoginEventsFeature.Status;
                    if (status === 'ENABLED') {
                        helpers.addResult(results, 0, 'GuardDuty RDS protection is enabled' , region, resource);
                    } else {
                        helpers.addResult(results, 2, 'GuardDuty RDS protection is disabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 2, 'GuardDuty RDS protection is disabled ' ,region, resource);
                }
                 
            });
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
