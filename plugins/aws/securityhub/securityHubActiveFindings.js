var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Security Hub No Active Findings',
    category: 'Security Hub',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Security Hub active findings do not exist in your AWS account.',
    more_info: 'AWS Security Hub provides you with a comprehensive view of your security state within AWS. It continuously monitors your environment using automated security checks based on AWS best practices and industry standards, and aggregates findings from various AWS services. Active findings should be remediated and archived to maintain a secure environment.',
    link: 'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings.html',
    recommended_action: 'Resolve the Security Hub findings and archive them.',
    apis: ['SecurityHub:describeHub', 'SecurityHub:getFindings'],
    settings: {
        securityhub_findings_fail: {
            name: 'Security Hub Findings Fail',
            description: 'Return a failing result if a finding has not been archived after these many hours',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '48'
        }
    },
    realtime_triggers: ['securityhub:EnableSecurityHub', 'securityhub:DisableSecurityHub', 'securityhub:BatchUpdateFindings'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        var config = {
            securityhub_findings_fail: parseInt(settings.securityhub_findings_fail || this.settings.securityhub_findings_fail.default)
        };

        async.each(regions.securityhub, function(region, rcb) {
            var describeHub = helpers.addSource(cache, source, ['securityhub', 'describeHub', region]);

            if (!describeHub) return rcb();

            if (describeHub.err && describeHub.err.code === 'InvalidAccessException') {
                helpers.addResult(results, 0, 'Security Hub is not enabled', region);
            } else if (describeHub.err || !describeHub.data) {
                helpers.addResult(results, 3, `Unable to query for Security Hub: ${helpers.addError(describeHub)}`, region);
            } else {
                var resource = describeHub.data.HubArn;
                const getFindings = helpers.addSource(cache, source, ['securityhub', 'getFindings', region]);

                if (!getFindings || !getFindings.data) {
                    helpers.addResult(results, 0, 'No active findings available', region, resource);
                    return rcb();
                } else if (getFindings.err) {
                    helpers.addResult(results, 3, `Unable to get SecurityHub findings: ${helpers.addError(getFindings)}`, region, resource);
                } else if (!getFindings.data.length) {
                    helpers.addResult(results, 0, 'No active findings available', region, resource);
                    return rcb();
                } else {
                    let activeFindings = getFindings.data.filter(finding => finding.CreatedAt &&
                        helpers.hoursBetween(new Date, finding.CreatedAt) > config.securityhub_findings_fail);

                    if (!activeFindings.length) {
                        helpers.addResult(results, 0,
                            'Security Hub has no active findings', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Security Hub has over ${activeFindings.length} active findings`, region, resource);
                    }
                }

            }

            return rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
