var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volumes Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    description: 'Ensure that Compute Optimizer EBS volume recommendations are in order to take the actions to optimize Amazon EBS volumes that are under-performing.',
    more_info: 'An EBS volume is considered optimized when Compute Optimizer determines that the volume is correctly provisioned to run your workload, based on the chosen volume type, volume size, and IOPS specification. For optimized resources, Compute Optimizer might sometimes recommend a new generation volume type.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ebs-recommendations.html',
    recommended_action: 'Enable Compute Optimizer Opt In options for EBS volume recommendations',
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

            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType === 'EbsVolume');
            if (findings) {
                let notOptimized = findings.summaries.find(summary => summary.name === 'NotOptimized');
                if (notOptimized.value){
                    helpers.addResult(results, 2,
                        `EBS volumes are not optimized,  NOT_OPTIMIZED: ${notOptimized.value}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All EBS volumes are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'No EBS volumes configured', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};