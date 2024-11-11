var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS GuardDuty Enabled',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that GuardDuty protection is enabled for EKS clusters.' ,
    more_info: 'Enabling GuardDuty EKS protection helps detect potential security threats in your EKS clusters by monitoring audit logs, user activities, and control plane operations. It provides enhanced security by offering proactive threat detection and automated alerting for suspicious activities and security issues within your AWS environment.',
    recommended_action: 'Enable GuardDuty EKS protection for all AWS accounts.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html',
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

            if (!listDetectors.data || !listDetectors.data.length) {
                helpers.addResult(results, 0, 'No GuardDuty detectors found', region);
                return rcb();
            }

            listDetectors.data.forEach(function(detectorId) {
                var resource = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
                var getDetector = helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);

                if (!getDetector) return;

                if (getDetector.err || !getDetector.data) {
                    helpers.addResult(results, 3, 'Unable to get GuardDuty detector: ' + helpers.addError(getDetector),region);
                    return;
                }

                var detector = getDetector.data;

                if (detector.DataSources &&
                    detector.DataSources.Kubernetes &&
                    detector.DataSources.Kubernetes.AuditLogs &&
                    detector.DataSources.Kubernetes.AuditLogs.Status &&
                    detector.DataSources.Kubernetes.AuditLogs.Status.toLowerCase() === 'disabled'){
                    helpers.addResult(results, 2, 'GuardDuty EKS protection is disabled', region, resource);
                } else {
                    helpers.addResult(results, 0, 'GuardDuty EKS protection is enabled', region, resource);
                }

            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
