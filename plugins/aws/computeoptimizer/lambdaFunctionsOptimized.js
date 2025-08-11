var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Function Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized Lambda Functions.',
    more_info: 'AWS Compute Optimizer generates memory size recommendations for AWS Lambda functions. A Lambda function is considered optimized when Compute Optimizer determines that its configured memory or CPU power (which is proportional to the configured memory) is correctly provisioned to run your workload.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-lambda-recommendations.html',
    recommended_action: 'Resolve Compute Optimizer recommendations for Lambda functions.',
    apis: ['ComputeOptimizer:getRecommendationSummaries'],
    realtime_triggers: ['ComputeOptimizer:UpdateEnrollmentStatus','lambda:CreateFunction','lambda:UpdateFunctionConfiguration','lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.computeoptimizer, function(region, rcb){
            var getRecommendationSummaries = helpers.addSource(cache, source,
                ['computeoptimizer', 'getRecommendationSummaries', region]);

            if (!getRecommendationSummaries) return rcb();

            if (getRecommendationSummaries && getRecommendationSummaries.err &&
                getRecommendationSummaries.err.name &&
                getRecommendationSummaries.err.name.toUpperCase() === 'OPTINREQUIREDEXCEPTION'){
                helpers.addResult(results, 0, 
                    'Compute Optimizer is not enabled', region);
                return rcb();
            }

            if (getRecommendationSummaries.err || !getRecommendationSummaries.data) {
                helpers.addResult(results, 3,
                    'Unable to get recommendation summaries: ' + helpers.addError(getRecommendationSummaries), region);
                return rcb();
            }

            if (!getRecommendationSummaries.data.length) {
                helpers.addResult(results, 0, 
                    'No Compute Optimizer recommendation summaries found', region);
                return rcb();
            }

            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType &&
                resourceType.recommendationResourceType.toUpperCase() === 'LAMBDAFUNCTION');
            if (findings) {
                let notOptimized = findings.summaries.find(notOpt => notOpt.name === 'NotOptimized');
                let Optimized = findings.summaries.find(Opt => Opt.name === 'Optimized');
                if (!notOptimized.value && !Optimized.value){
                    helpers.addResult(results, 0,
                        'No recommendations found for Lambda functions', region);
                } else if (notOptimized.value){
                    helpers.addResult(results, 2,
                        `Found ${notOptimized.value} unoptimized Lambda functions`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Lambda Functions are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'Recommendation summaries are not configured for Lambda functions', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};