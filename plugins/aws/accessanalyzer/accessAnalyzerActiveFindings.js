var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Access Analyzer Active Findings',
    category: 'IAM',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensure that IAM Access analyzer findings are reviewed and resolved by taking all necessary actions.',
    more_info: 'IAM Access Analyzer helps you evaluate access permissions across your AWS cloud environment and gives insights into intended access to your resources. It can monitor the access policies associated with S3 buckets, KMS keys, SQS queues, IAM roles and Lambda functions for permissions changes. ' +
        'You can view IAM Access Analyzer findings at any time. Work through all of the findings in your account until you have zero active findings.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-work-with-findings.html',
    recommended_action: 'Investigate into active findings in your account and do the needful until you have zero active findings.',
    apis: ['AccessAnalyzer:listAnalyzers', 'AccessAnalyzer:listFindings', 'AccessAnalyzer:listFindingsV2'],
    realtime_triggers: ['accessanalyzer:CreateAnalyzer','accessanalyzer:DeleteAnalyzer','accessanalyzer:CreateArchiveRule','accessanalyzer:StartResourceScan'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.accessanalyzer, function(region, rcb){        
            var listAnalyzers = helpers.addSource(cache, source,
                ['accessanalyzer', 'listAnalyzers', region]);

            if (!listAnalyzers) return rcb();

            if (listAnalyzers.err || !listAnalyzers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for IAM Access Analyzer analyzers: ${helpers.addError(listAnalyzers)}`, region);
                return rcb();
            }

            if (!listAnalyzers.data.length) {
                helpers.addResult(results, 0, 'No IAM Access Analyzer analyzers found', region);
                return rcb();
            }

            for (let analyzer of listAnalyzers.data) {
                if (!analyzer.arn) continue;

                let resource = analyzer.arn;
                let totalFiltered = [];

                var listFindings = helpers.addSource(cache, source,
                    ['accessanalyzer', 'listFindings', region, analyzer.arn]);

                if (listFindings && !listFindings.err && listFindings.data) {
                    let filtered = listFindings.data.findings.filter(finding => finding.status === 'ACTIVE');
                    totalFiltered = totalFiltered.concat(filtered);
                }

                var listFindingsV2 = helpers.addSource(cache, source,
                    ['accessanalyzer', 'listFindingsV2', region, analyzer.arn]);

                if (listFindingsV2 && !listFindingsV2.err && listFindingsV2.data) {
                    let filteredv2 = listFindingsV2.data.findings.filter(finding => finding.status === 'ACTIVE');
                    totalFiltered = totalFiltered.concat(filteredv2);
                }
                
                if ((!listFindings || listFindings.err || !listFindings.data) && (!listFindingsV2 || listFindingsV2.err || !listFindingsV2.data)) {
                    helpers.addResult(results, 3,
                        `Unable to IAM Access Analyzer findings: ${helpers.addError(listFindings)} ${helpers.addError(listFindingsV2)}`,
                        region, resource);
                    continue;
                } 
                
                if (!totalFiltered.length) {
                    helpers.addResult(results, 0,
                        'Amazon IAM Access Analyzer has no active findings',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Amazon IAM Access Analyzer has active findings',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};