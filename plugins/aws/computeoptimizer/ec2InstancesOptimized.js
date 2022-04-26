var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Instances Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    description: 'Ensure that Compute Optimizer EC2 findings are in order to take the actions to optimize Amazon EC2 instances that are under-provisioned and over-provisioned.',
    more_info: 'An EC2 instance is considered optimized when all specifications of an instance, such as CPU, memory, and network, meet the performance requirements of your workload, and the instance is not over-provisioned. For optimized instances, Compute Optimizer might sometimes recommend a new generation instance type.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html',
    recommended_action: 'Enable Compute Optimizer Opt In options for Ec2 instances recommendations',
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

            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType === 'Ec2Instance');
            if (findings) {
                let underProvisioned = findings.summaries.find(underProv => underProv.name === 'UNDER_PROVISIONED' );
                let optimized = findings.summaries.find(opt => opt.name === 'OPTIMIZED' );
                let overProvisioned = findings.summaries.find(overProv => overProv.name === 'OVER_PROVISIONED' );
                if (!underProvisioned.value && !overProvisioned.value && !optimized.value){
                    helpers.addResult(results, 0,
                        'EC2 instances have no recommendations enabled', region);
                } else if (underProvisioned.value || overProvisioned.value){
                    helpers.addResult(results, 2,
                        `EC2 instances are not optimized,  under provisioned: ${underProvisioned.value}, over provisioned: ${underProvisioned.value} `, region);
                } else {
                    helpers.addResult(results, 0,
                        'All EC2 instances are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'No EC2 instances configured', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
