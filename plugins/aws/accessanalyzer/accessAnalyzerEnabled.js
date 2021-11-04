var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Access Analyzer Enabled',
    category: 'IAM',
    domain: 'Management and Governance',
    description: 'Ensure that IAM Access analyzer is enabled for all regions.',
    more_info: 'Access Analyzer allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access. It analyzes only policies that are applied to resources in the same AWS region.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html',
    recommended_action: 'Enable Access Analyzer for all regions',
    apis: ['AccessAnalyzer:listAnalyzers'],
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
                    'Unable to list Access Analyzers: ' + helpers.addError(listAnalyzers), region);
                return rcb();
            }

            if (!listAnalyzers.data.length) {
                helpers.addResult(results, 2,
                    'Access Analyzer is not configured', region);
                return rcb();
            }

            var found = listAnalyzers.data.find(analyzer => analyzer.status.toLowerCase() == 'active');
            if (found) {
                helpers.addResult(results, 0,
                    'Access Analyzer is enabled', region, found.arn);
            } else {
                helpers.addResult(results, 2,
                    'Access Analyzer is not enabled', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
