var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Function Findings Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    description: 'Ensure that Compute Optimizer Lambda Function findings are in order to take actions to optimize Amazon Lambda Function that are under-provisioned and over-provisioned.',
    more_info: 'AWS Compute Optimizer generates memory size recommendations for AWS Lambda functions. A Lambda function is considered optimized when Compute Optimizer determines that its configured memory or CPU power (which is proportional to the configured memory) is correctly provisioned to run your workload.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-lambda-recommendations.html',
    recommended_action: 'Enable Compute Optimizer Opt In options for AWS Lambda function findings',
    apis: ['ComputeOptimizer:getRecommendationSummaries'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.computeoptimizer, function(region, rcb){
            var getRecommendationSummaries = helpers.addSource(cache, source,
                ['computeoptimizer', 'getRecommendationSummaries', region]);

            if (!getRecommendationSummaries) return rcb();

            if (getRecommendationSummaries && getRecommendationSummaries.err && 
                getRecommendationSummaries.err.code === 'OptInRequiredException'){
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
                    'Optimization for summaries is not configured', region);
                return rcb();
            }

            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType === 'LambdaFunction');
            if (findings) {
                let notOptimized = findings.summaries.find(notOpt => notOpt.name === 'NotOptimized');
                let Optimized = findings.summaries.find(Opt => Opt.name === 'Optimized');
                if (!notOptimized.value && !Optimized.value){
                    helpers.addResult(results, 0,
                        'Lambda Functions have no recommendations enabled', region);
                } else if (notOptimized.value){
                    helpers.addResult(results, 2,
                        `Lambda Functions are not optimized,  NOT_OPTIMIZED Functions: ${notOptimized.value}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Lambda Functions are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'No Lambda function findings configured', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};