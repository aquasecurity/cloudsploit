var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Inspector Findings Check',
    category: 'Inspector',
    domain: 'Security & Compliance',
    description: 'Check for Amazon Inspector Findings to ensure that your systems are configured securely.',
    more_info: 'Review findings to identify and address security issues in your AWS resources.',
    recommended_action: 'Investigate and remediate security findings based on assessment results.',
    link: 'https://docs.aws.amazon.com/inspector/latest/userguide/inspector_findings.html',
    apis: ['Inspector:listFindings','Inspector:describeFindings', 'Inspector:listAssessmentRuns','Inspector:describeAssessmentRuns', 'Inspector:listAssessmentTemplates'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
    
        async.each(regions.inspector, function(region, rcb) {
            var listFindings = helpers.addSource(cache, source,
                ['inspector', 'listFindings', region]);
            
           
            if (!listFindings) return rcb();

            if (listFindings.err || !listFindings.data) {
                helpers.addResult(results, 3,
                    'Unable to query Inspector Findings: ' + helpers.addError(listFindings), region);
                return rcb();
            }
            if (!listFindings.data.length) {
                helpers.addResult(results, 0, 'No Inspector Findings found', region);
                return rcb();
            }
            var listAssessmentRuns = helpers.addSource(cache, source,
                ['inspector', 'listAssessmentRuns', region]);
            
            var listAssessmentTemplates = helpers.addSource(cache, source,
                ['inspector', 'listAssessmentTemplates', region]);
            
            var describeFindings = [];

            async.each(listFindings.data, function(findArn) {
                describeFindings.push(helpers.addSource(cache, source,
                    ['inspector', 'describeFindings', region, findArn]));
            });

            var describeAssessmentRuns = [];

            async.each(listAssessmentRuns.data, function(runArn) {
                describeAssessmentRuns.push(helpers.addSource(cache, source,
                    ['inspector', 'describeAssessmentRuns', region, runArn]));
            });
            async.each(listAssessmentTemplates.data, function(templateArn, tcb) {
                var findingsCount = 0;
                var matchingRuns = describeAssessmentRuns.filter((e) => e.data.assessmentRuns[0].assessmentTemplateArn == templateArn);
                async.each(matchingRuns, function(runObj, acb) {
                    if (describeFindings.length) {
                        findingsCount =findingsCount + describeFindings.filter((e) => e.data.findings[0].serviceAttributes.assessmentRunArn == runObj.data.assessmentRuns[0].arn).length;
                        acb();
                    }
                }, function(err) {
                    if (!err) {
                        if (findingsCount>0) {
                            helpers.addResult(results, 2, `Assessment Template has ${findingsCount} Findings`, region, templateArn);
                        } else {
                            helpers.addResult(results, 0, 'Assessment Template has no Findings', region, templateArn);
                        }
                    }

                    tcb();
                });
            }, function() {
                rcb();
            });
        }, function(){
            callback(null, results, source); 
        });
    }
};
