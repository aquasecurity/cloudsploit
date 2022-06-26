var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volumes Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    description: 'Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized EBS Volumes.',
    more_info: 'An EBS volume is considered optimized when Compute Optimizer determines that the volume is correctly provisioned to run your workload, based on the chosen volume type, volume size, and IOPS specification. For optimized resources, Compute Optimizer might sometimes recommend a new generation volume type.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ebs-recommendations.html',
    recommended_action: 'Resolve Compute Optimizer recommendations for EBS volumes.',
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
                getRecommendationSummaries.err.code &&
                getRecommendationSummaries.err.code.toUpperCase() === 'OPTINREQUIREDEXCEPTION'){
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

            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType === 'EbsVolume');
            if (findings) {
      
                let notOptimized = findings.summaries.find(notOpt => notOpt.name === 'NotOptimized');
                let optimized = findings.summaries.find(opt => opt.name === 'Optimized');
                
                if (!notOptimized.value  && !optimized.value){
                    helpers.addResult(results, 0,
                        'No recommendations found for EBS volumes', region);
                } else if (notOptimized.value){
                    helpers.addResult(results, 2,
                        `Found ${notOptimized.value} unoptimized EBS volumes`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All EBS volumes are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'Recommendation summaries are not configured for EBS Volumes', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};