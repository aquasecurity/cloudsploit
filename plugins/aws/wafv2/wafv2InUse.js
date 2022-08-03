var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS WAFV2 In Use',
    category: 'WAF',
    domain: 'Availability',
    description: 'Ensure that AWS Web Application Firewall V2 (WAFV2) is in use to achieve availability and security for AWS-powered web applications.',
    more_info: 'Using WAF for your web application running in AWS environment can help you against common web-based attacks, SQL injection attacks, DDOS attacks and more.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html',
    recommended_action: 'Create one or more WAF ACLs with proper actions and rules',
    apis: ['WAFV2:listWebACLs'],

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

            if (!listWebACLs.data.length) {
                helpers.addResult(results, 2, 'WAFV2 is not enabled', region);
            } else {
                helpers.addResult(results, 0, 'WAFV2 is enabled', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};