var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web ACL Rules Default Action',
    category: 'WAF',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensure that default Web ACL action is set to "Block" for ACL rules with allow action.',
    more_info: 'Web ACL default action determines whether the incoming request is allowed or blocked when none of the rules are matched. As a security best practice, make sure it is set to ‘Block’ when you have configured web ACL rules with allow actions. This will limit the number of users accessing your web app and will reduce the scope of malicious attacks.',
    link: 'https://docs.aws.amazon.com/waf/latest/APIReference/API_DefaultAction.html',
    recommended_action: 'Modify Web ACL and set default action to block requests.',
    apis: ['WAFV2:listWebACLs', 'WAFV2:getWebACL'],
    realtime_triggers: ['wafv2:CreateWebACL', 'wafv2:UpdateWebACL','wafv2:DeleteWebACL'],

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
                
                if (!getWebACL || !getWebACL.data || getWebACL.err || !getWebACL.data.WebACL){
                    helpers.addResult(results, 3,
                        'Unable to get web ACL details: ' + helpers.addError(listWebACLs), region, webAcl.ARN);
                    continue;
                }

                if (getWebACL.data.WebACL.DefaultAction  && getWebACL.data.WebACL.DefaultAction.Block ){
                    helpers.addResult(results, 0, 'Default action for web ACL rule is set to Block', region, webAcl.ARN);
                } else {
                    helpers.addResult(results, 2, 'Default action for web ACL rule is not set to Block', region, webAcl.ARN);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
