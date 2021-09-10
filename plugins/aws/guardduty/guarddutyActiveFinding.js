var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty Active Findings',
    category: 'GuardDuty',
    description: 'Ensures that no high severity active findings exist',
    more_info: 'High severity level indicates that the resource in question is compromised and is actively being used for unauthorized purposes.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html',
    recommended_action: 'Resolve the security risk indicated by the finding',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:listFindings', 'GuardDuty:getDetector', 'GuardDuty:getFindings', 'STS:getCallerIdentity'],
    settings: {
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};

        const acctRegion = helpers.defaultRegion(settings);
        const awsOrGov = helpers.defaultPartition(settings);
        const accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        const regions = helpers.regions(settings);

        regions.guardduty.forEach((region) => {
            const listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
            if (!listDetectors) return;
            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    'Unable to list GuardDuty detectors: ' + helpers.addError(listDetectors), region);
                return;
            }
            if (!listDetectors.data.length) {
                helpers.addResult(results, 2, 'No GuardDuty detectors found', region);
                return;
            }
            for (let detectorId of listDetectors.data) {
                const resource = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
                const getDetector =  helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);
                if (!getDetector) continue;
                if (getDetector.err || !getDetector.data) {
                    helpers.addResult(results, 3, `Unable to get GuardDuty detector: ${helpers.addError(listDetectors)}`, region, resource);
                    continue;
                }
                if (getDetector.data.Status && getDetector.data.Status.toUpperCase() !== 'ENABLED') {
                    helpers.addResult(results, 2, 'GuardDuty detector is disabled', region, resource);
                    continue;
                }
                const getFindings = helpers.addSource(cache, source, ['guardduty', 'getFindings', region, detectorId]);
                
                if (!getFindings) {
                    helpers.addResult(results, 0, 'No findings available', region, resource);
                    continue;
                }
                if (getFindings.err || !getFindings.data) {
                    helpers.addResult(results, 3, `Unable to get GuardDuty findings: ${helpers.addError(getFindings)}`, region, resource);
                    continue;
                }
                if (getFindings.data.Findings) {
                    const severityFindings = getFindings.data.Findings.find(finding => finding.Severity && finding.Severity >= 7.0);
                    const status = severityFindings ? 2: 0;
                    helpers.addResult(results, status, `High severity findings ${status == 0? 'not ': ''}found`, region, resource);
                }  else {
                    helpers.addResult(results, 0, 'No findings available', region, resource);
                }       
            }
        });

        callback(null, results, source);
    }
};
