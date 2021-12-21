var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty No Active Findings',
    category: 'GuardDuty',
    domain: 'Management and Governance',
    description: 'Ensure that GurardDuty active/current findings does not exist in your AWS account.',
    more_info: 'Amazon GuardDuty is a threat detection service that continuously monitors your AWS accounts and workloads for malicious activity and delivers detailed security findings for visibility and remediation. ' +
        'These findings should be acted upon and archived after they have been remediated in order to follow security best practices. ' +
        'If a finding had not been archived after set amount of time, Aqua CSPM plugin will display a FAIL result.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html',
    recommended_action: 'Resolve the GuardDuty findings and archive them',
    apis: ['GuardDuty:listDetectors', 'GuardDuty:listFindings', 'GuardDuty:getDetector', 'GuardDuty:getFindings',
        'STS:getCallerIdentity'],
    settings: {
        guardduty_findings_fail: {
            name: 'GuardDuty Findings Fail',
            description: 'Return a failing result if a finding has not been archived after these many hours',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '48'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};

        const acctRegion = helpers.defaultRegion(settings);
        const awsOrGov = helpers.defaultPartition(settings);
        const accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        const regions = helpers.regions(settings);

        var config = {
            guardduty_findings_fail: parseInt(settings.guardduty_findings_fail || this.settings.guardduty_findings_fail.default)
        };

        regions.guardduty.forEach((region) => {
            const listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);

            if (!listDetectors) return;

            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    'Unable to list GuardDuty detectors: ' + helpers.addError(listDetectors), region);
                return;
            }

            if (!listDetectors.data.length) {
                helpers.addResult(results, 0, 'No GuardDuty detectors found', region);
                return;
            }

            for (let detectorId of listDetectors.data) {
                const resource = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
                
                const getDetector = helpers.addSource(cache, source, ['guardduty', 'getDetector', region, detectorId]);

                if (!getDetector || getDetector.err || !getDetector.data) {
                    helpers.addResult(results, 3, `Unable to get GuardDuty detector: ${helpers.addError(listDetectors)}`, region, resource);
                    continue;
                }

                const getFindings = helpers.addSource(cache, source, ['guardduty', 'getFindings', region, detectorId]);

                if (!getFindings) {
                    helpers.addResult(results, 0, 'No active findings available', region, resource);
                    continue;
                }

                if (getFindings.err || !getFindings.data || !getFindings.data.Findings) {
                    helpers.addResult(results, 3, `Unable to get GuardDuty findings: ${helpers.addError(getFindings)}`, region, resource);
                    continue;
                }

                if (!getFindings.data.Findings.length) {
                    helpers.addResult(results, 0, 'No active findings available', region, resource);
                    continue;
                }

                let activeFindings = getFindings.data.Findings.filter(finding => finding.CreatedAt &&
                    helpers.hoursBetween(new Date, finding.CreatedAt) > config.guardduty_findings_fail);
                let status = (activeFindings && activeFindings.length) ? 2 : 0;

                helpers.addResult(results, status,
                    `GuardDuty has ${status == 0 ? 0 : activeFindings.length} active finding(s)`, region, resource);
            }
        });

        callback(null, results, source);
    }
}; 