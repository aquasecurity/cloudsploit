var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web ACL Logging Enabled',
    category: 'WAF',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensure that AWS WAFV2 Web Access Control Lists (ACLs) have logging enabled.',
    more_info: 'Enabling logging for Web ACL allows detailed logging of web requests that match defined rules within the WAF Web ACL. This enables comprehensive monitoring, analysis, and troubleshooting of security threats and traffic patterns within your web application.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html',
    recommended_action: 'Modify WAFV2 Web ACL and enable logging.',
    apis: ['WAFV2:listWebACLs','WAFV2:getLoggingConfiguration'],
    realtime_triggers: ['wafv2:CreateWebACL', 'wafv2:DeleteWebAcl', 'wafv2:PutLoggingConfiguration'],

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

                let getLoggingConfiguration = helpers.addSource(cache, source,
                    ['wafv2', 'getLoggingConfiguration', region, webAcl.ARN]);

                if (getLoggingConfiguration.err && 
                    getLoggingConfiguration.err.code === 'WAFNonexistentItemException') {
                    helpers.addResult(results, 2, 'Logging for web ACL is disabled', region, webAcl.ARN);
                    continue;

                } else if (!getLoggingConfiguration || 
                    !getLoggingConfiguration.data ||
                    getLoggingConfiguration.err || 
                    !getLoggingConfiguration.data.LoggingConfiguration){
                    helpers.addResult(results, 3,
                        'Unable to get WAFV2 web ACL logging configuration: ' + helpers.addError(listWebACLs), region, webAcl.ARN);
                    continue;
                }

                if (getLoggingConfiguration.data.LoggingConfiguration){
                    helpers.addResult(results, 0, 'Logging for web ACL is enabled', region, webAcl.ARN);
                } else {
                    helpers.addResult(results, 2, 'Logging for web ACL is disabled', region, webAcl.ARN);
                }
            }
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};