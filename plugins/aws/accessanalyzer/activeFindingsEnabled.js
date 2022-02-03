var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Access Analyzer Active Findings',
    category: 'IAM',
    domain: 'Management and Governance',
    description: 'Ensure that IAM Access analyzer findings are reviewed for resolving security issues by taking all necessary actions.',
    more_info: 'Access Analyzer review all of the findings in your account to determine whether the sharing is expected and approved. If the sharing identified in the finding is expected, you can archive the finding. ' +
        'When you archive a finding, the status is changed to Archived, and the finding is removed from the Active findings list. The finding is not deleted. You can view your archived findings at any time. Work through all of the findings in your account until you have zero active findings.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-work-with-findings.html',
    recommended_action: 'Enable Access Analyzer to work through all of the findings in your account until you have zero active findings',
    apis: ['AccessAnalyzer:listAnalyzers', 'AccessAnalyzer:listFindings'],

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
                    `Unable to query for IAM access analyzers: ${helpers.addError(listAnalyzers)}`,region);
                return rcb();
            }

            if (!listAnalyzers.data.length) {
                helpers.addResult(results, 0, 'No IAM access analyzers found', region);
                return rcb();
            }

            for (let analyzer of listAnalyzers.data) {
                if (!analyzer.arn) continue;

                let resource = analyzer.arn;

                var listFindings = helpers.addSource(cache, source,
                    ['accessanalyzer', 'listFindings', region, analyzer.arn]);

                if (!listFindings || listFindings.err || !listFindings.data) {
                    helpers.addResult(results, 3,
                        `Unable to query list findings: ${helpers.addError(listFindings)}`,
                        region, resource);
                    continue;
                } 
                
                let filtered = listFindings.data.findings.filter(finding => finding.status === 'ACTIVE');
                if (!filtered.length) {
                    helpers.addResult(results, 0,
                        'Amazon IAM access analyzer have no active findings',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Amazon IAM access analyzer has active findings',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};