var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty Active Findings',
    category: 'GuardDuty',
    description: 'Ensures that no high severity active findings exist',
    more_info: 'High severity level indicates that the resource in question is compromised and is actively being used for unauthorized purposes.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html',
    recommended_action: 'Resolve the security risk indicated by the finding',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:listFindings', 'GuardDuty:getFindings', 'STS:getCallerIdentity'],
    settings: {
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var regions = helpers.regions(settings);

        regions.guardduty.forEach((region) => {
            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
            if (!listDetectors) return;
            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    'Unable to list guardduty detectors: ' + helpers.addError(listDetectors), region);
                return;
            }
            if (!listDetectors.data.length) {
                helpers.addResult(results, 2, 'No GuardDuty detectors found', region);
                return;
            }
            for (let detectorId of listDetectors.data) {
                var getFindings = helpers.addSource(cache, source, ['guardduty', 'getFindings', region, detectorId]);
                var arn = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
            
            }
        }, function(){
            callback(null, results, source);
        });
    }
};
