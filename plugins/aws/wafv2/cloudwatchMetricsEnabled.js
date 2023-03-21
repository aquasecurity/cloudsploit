var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS WAFV2 Cloudwatch Metrics Enabled',
    category: 'WAF',
    domain: 'Availability',
    description: 'Ensure that AWS CloudWatch metrics is enabled for WAFV2 Web ACL Rules.',
    more_info: 'As a security best practice, make sure to enable CloudWatch metrics for all the configured Web ACL rules. These metrics are useful in understanding the access patterns for your web application like allowed, blocked or passed requests based on the rules evaluation.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html',
    recommended_action: 'Create one or more WAF ACLs with proper actions and rules',
    apis: ['WAFV2:listWebACLs', 'WAFV2:getWebACL'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = { };
        var regions = helpers.regions(settings);

        async.each(regions.wafregional, function(region, rcb){
            var listWebACLs = helpers.addSource(cache, source,
                ['wafv2', 'listWebACLs', region]);

            if (!listWebACLs) return rcb();

            if (listWebACLs.err || !listWebACLs.data) {
                helpers.addResult(results, 3,
                    'Unable to list WAFV2 web ACLs: ' + helpers.addError(listWebACLs), region);
                return rcb();
            }

            for (let webAcl of listWebACLs.data){
                let getWebACL = helpers.addSource(cache, source,
                    ['wafv2', 'getWebACL', region, webAcl.ARN]);
                
                if (!getWebACL || !getWebACL.data || getWebACL.err){
                    helpers.addResult(results, 3,
                        'Unable to get web acl details: ' + helpers.addError(listWebACLs), region);
                    return rcb();
                }
                if (!getWebACL.data.WebACL.ARN){
                    continue;
                }
                if (getWebACL.data.WebACL.VisibilityConfig && getWebACL.data.WebACL.VisibilityConfig.CloudWatchMetricsEnabled &&
                getWebACL.data.WebACL.VisibilityConfig.CloudWatchMetricsEnabled === true){
                    helpers.addResult(results, 0, 'Cloud watch metrics are enabled for web ACL rule', region, getWebACL.data.WebACL.ARN);
                } else {
                    helpers.addResult(results, 2, 'Cloud watch metrics are not enabled for web ACL rule', region, getWebACL.data.WebACL.ARN);
                }

            } 
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};