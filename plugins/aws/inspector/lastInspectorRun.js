var async = require('async');
var helpers = require('../../../helpers/aws');
var moment = require('moment');

module.exports = {
    title: 'Amazon Inspector Assessment Last Run Check',
    category: 'Inspector',
    domain: 'Security & Compliance',
    description: 'Ensure that Amazon Inspector has run for a given Assessment template every n days.',
    more_info: 'Amazon Inspector helps improve the security and compliance of your AWS resources by identifying potential security issues.',
    recommended_action: 'Review and manage Amazon Inspector assessment runs for the specified template.',
    link: 'https://docs.aws.amazon.com/inspector/lalistAssessmentTemplates/userguide/inspector_assessments.html',
    apis: ['Inspector:listAssessmentTemplates', 'Inspector:listAssessmentRuns', 'Inspector:describeAssessmentRuns'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var daysThreshold = 7; 
    
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
            async.each(listAssessmentTemplates.data, function(templateArn, tcb) {
                var listAssessmentRuns = helpers.addSource(cache, source,
                    ['inspector', 'listAssessmentRuns', region, templateArn]);
                var hasRunWithin7Days = false;
                var currentDate = moment();

                async.each(listAssessmentRuns.data.assessmentRunArns, function(runArn, acb) {
                    var describeAssessmentRuns = helpers.addSource(cache, source,
                        ['inspector', 'describeAssessmentRuns', region, runArn]);
                    var runCompletionDate = moment(describeAssessmentRuns.data.assessmentRuns[0].completedAt);
                    var timeDifference = currentDate.diff(runCompletionDate, 'days');
    
                    if (timeDifference <= daysThreshold ) {
                        hasRunWithin7Days = true;
                    }
                    acb();
                }, function(err) {
                    if (!err) {
                        if (hasRunWithin7Days) {
                            helpers.addResult(results, 0, 'Assessment template run within the last 7 days', region, templateArn);
                        } else {
                            helpers.addResult(results, 2, 'Assessment template not run in the last 7 days', region, templateArn);
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
