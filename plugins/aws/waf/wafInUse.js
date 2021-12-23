var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS WAF In Use',
    category: 'WAF',
    domain: 'Availability',
    description: 'Ensure that AWS Web Application Firewall (WAF) is in use to achieve availability and security for AWS-powered web applications.',
    more_info: 'Using WAF for your web application running in AWS environment can help against common web-based attacks, SQL injection attacks, DDOS attacks and more.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html',
    recommended_action: 'Create one or more WAF ACLs with proper actions and rules',
    apis: ['WAF:listWebACLs', 'WAFRegional:listWebACLs'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.wafregional, function(region, rcb){
            var listRegionalWebACLs = helpers.addSource(cache, source,
                ['wafregional', 'listWebACLs', region]);

            if (!listRegionalWebACLs) return rcb();

            if (listRegionalWebACLs.err || !listRegionalWebACLs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for WAF: ' + helpers.addError(listRegionalWebACLs), region);
                return rcb();
            }

            if (!listRegionalWebACLs.data.length) {
                helpers.addResult(results, 2, 'WAF is not enabled', region);
            } else {
                helpers.addResult(results, 0, 'WAF is enabled', region);
            }

            rcb();
        }, function(){
            var listGlobalWebACLs = helpers.addSource(cache, source,
                ['waf', 'listWebACLs', regions.waf]);

            if (!listGlobalWebACLs) return callback(null, results, source);

            if (listGlobalWebACLs.err || !listGlobalWebACLs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Global WAF: ' + helpers.addError(listGlobalWebACLs));
                return callback(null, results, source);
            }

            if (!listGlobalWebACLs.data.length) {
                helpers.addResult(results, 2, 'WAF is not enabled', 'global');
            } else {
                helpers.addResult(results, 0, 'WAF is enabled', 'global');
            }

            callback(null, results, source);
        });
    }
};
