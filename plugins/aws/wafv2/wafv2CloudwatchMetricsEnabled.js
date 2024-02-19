var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS WAFV2 Cloudwatch Metrics Enabled',
    category: 'WAF',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensure that AWS CloudWatch metrics is enabled for WAFV2 Web ACL rules.',
    more_info: 'As a security best practice, make sure to enable CloudWatch metrics for all the configured Web ACL rules. These metrics are useful in understanding the access patterns for your web application like allowed, blocked or passed requests based on the rules evaluation.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html',
    recommended_action: 'Modify WAFv2 and enable cloud watch metrics.',
    apis: ['WAFV2:listWebACLs', 'WAFV2:getWebACL'],
    realtime_triggers: ['wafv2:CreateWebACL','wafv2:updateWebACL', 'wafv2:DeleteWebACL'],

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
                if (!webAcl.ARN) continue;

                let getWebACL = helpers.addSource(cache, source,
                    ['wafv2', 'getWebACL', region, webAcl.ARN]);
                
                if (!getWebACL || !getWebACL.data || getWebACL.err){
                    helpers.addResult(results, 3,
                        'Unable to get web acl details: ' + helpers.addError(listWebACLs), region, webAcl.ARN);
                    continue;
                }

                if (getWebACL.data.WebACL &&
                getWebACL.data.WebACL.VisibilityConfig && getWebACL.data.WebACL.VisibilityConfig.CloudWatchMetricsEnabled){
                    helpers.addResult(results, 0, 'WAFV2 web ACL rule has CloudWatch metrics enabled', region, webAcl.ARN);
                } else {
                    helpers.addResult(results, 2, 'WAFV2 web ACL rule does not have CloudWatch metrics enabled', region, webAcl.ARN);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};