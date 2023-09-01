var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Inspector Assessment Exclusion Check',
    category: 'Inspector',
    domain: 'Security & Compliance',
    description: 'Check assessment exclusions to ensure successful assessment runs.',
    more_info: 'Resolve exclusion issues to enable complete security checks in Amazon Inspector assessments.',
    recommended_action: 'Review and resolve assessment exclusions as per the provided steps.',
    link: 'https://docs.aws.amazon.com/inspector/latest/userguide/inspector_exclusions.html',
    apis: ['Inspector:listAssessmentTemplates', 'Inspector:listAssessmentRuns', 'Inspector:describeAssessmentRuns', 'Inspector:listExclusions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
    
        async.each(regions.inspector, function(region, rcb) {
            var listAssessmentTemplates = helpers.addSource(cache, source,
                ['inspector', 'listAssessmentTemplates', region]);
            
           
            if (!listAssessmentTemplates) return rcb();

            if (listAssessmentTemplates.err || !listAssessmentTemplates.data) {
                helpers.addResult(results, 3,
                    'Unable to query Assessment Templates: ' + helpers.addError(listAssessmentTemplates), region);
                return rcb();
            }

            if (!listAssessmentTemplates.data.length) {
                helpers.addResult(results, 0, 'No Assessment Templates found', region);
                return rcb();
            }
            var listAssessmentRuns = helpers.addSource(cache, source,
                ['inspector', 'listAssessmentRuns', region]);
            
            async.each(listAssessmentTemplates.data, function(templateArn, tcb) {
                var latestRun = {};

                async.each(listAssessmentRuns.data, function(runArn, acb) {
                    var describeAssessmentRuns = helpers.addSource(cache, source,
                        ['inspector', 'describeAssessmentRuns', region, runArn]);
                    if (describeAssessmentRuns.data.assessmentRuns[0].assessmentTemplateArn == templateArn) {
                        var listExclusions= helpers.addSource(cache, source,
                            ['inspector', 'listExclusions', region, runArn]);
                        
                        if (!Object.keys(latestRun).length) {
                            latestRun = {
                                completedAt: describeAssessmentRuns.data.assessmentRuns[0].completedAt,
                                exclusionCount: listExclusions.data.exclusionArns.length,
                            };
                        } else if (latestRun.completedAt < describeAssessmentRuns.data.assessmentRuns[0].completedAt){
                            latestRun = {
                                completedAt: describeAssessmentRuns.data.assessmentRuns[0].completedAt,
                                exclusionCount: listExclusions.data.exclusionArns.length,
                            };
                        }
                    }
                    acb();
                }, function(err) {
                    if (!err) {
                        if (latestRun.exclusionCount) {
                            helpers.addResult(results, 2, `Assessment Template has ${latestRun.exclusionCount} Exclusions`, region, templateArn);
                        } else {
                            helpers.addResult(results, 0, 'Assessment Template has no Exclusions', region, templateArn);
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
