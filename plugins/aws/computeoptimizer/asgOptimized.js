var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Group Optimized',
    category: 'Compute Optimizer',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized Auto Scaling groups.',
    more_info: 'An Auto Scaling group is considered optimized when Compute Optimizer determines that the group is correctly provisioned to run your workload, based on the chosen instance type. For optimized Auto Scaling groups, Compute Optimizer might sometimes recommend a new generation instance type.',
    link: 'https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-asg-recommendations.html',
    recommended_action: 'Resolve Compute Optimizer recommendations for Auto Scaling groups.',
    apis: ['ComputeOptimizer:getRecommendationSummaries'],
    realtime_triggers: ['ComputeOptimizer:UpdateEnrollmentStatus','autoscaling:CreateAutoScalingGroup','autoscaling:UpdateAutoScalingGroup','autoscaling:StartInstanceRefresh','autoscaling:DeleteAutoScalingGroup'],

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
                resourceType.recommendationResourceType.toUpperCase() === 'AUTOSCALINGGROUP');
            if (findings) {
                
                let notOptimized = findings.summaries.find(notOpt => notOpt.name && notOpt.name.toUpperCase() === 'NOT_OPTIMIZED');
                let Optimized = findings.summaries.find(opt => opt.name && opt.name.toUpperCase() === 'OPTIMIZED');
      
                if (!notOptimized.value && !Optimized.value){
                    helpers.addResult(results, 0,
                        'No recommendations found for Auto Scaling groups', region);
                } else if (notOptimized.value){
                    helpers.addResult(results, 2,
                        `Found ${notOptimized.value} unoptimized Auto Scaling groups`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Auto Scaling groups are optimized', region);
                }
            } else {
                helpers.addResult(results, 2,
                    'Recommendation summaries are not configured for Auto Scaling groups', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
