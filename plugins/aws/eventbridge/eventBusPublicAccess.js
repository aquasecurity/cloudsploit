var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Event Bus Public Access',
    category: 'EventBridge',
    domain: 'Management and Governance',
    severity: 'HIGH',
    description: 'Ensure that EventBridge event bus is configured to prevent exposure to public access.',
    more_info: 'The default event bus in your Amazon account only allows events from one account. You can grant additional permissions to an event bus by attaching a resource-based policy to it.',
    link: 'https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-bus-perms.html',
    recommended_action: 'Configure EventBridge event bus policies that allow access to whitelisted/trusted account principals but not public access.',
    apis: ['EventBridge:listEventBuses', 'STS:getCallerIdentity'],
    settings: {
        event_bus_policy_condition_keys: {
            name: 'Event Bus Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount, aws:SourceArn',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceOwner,aws:SourceArn,aws:SourceAccount'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config = {
            event_bus_policy_condition_keys: settings.event_bus_policy_condition_keys || this.settings.event_bus_policy_condition_keys.default
        };
        config.event_bus_policy_condition_keys = config.event_bus_policy_condition_keys.replace(/\s/g, '');
        var allowedConditionKeys = config.event_bus_policy_condition_keys.split(',');

        async.each(regions.eventbridge, function(region, rcb){
            var listEventBuses = helpers.addSource(cache, source,
                ['eventbridge', 'listEventBuses', region]);  

            if (!listEventBuses) return rcb();

            if (listEventBuses.err || !listEventBuses.data) {
                helpers.addResult(results, 3,
                    'Unable to list event bus: ' + helpers.addError(listEventBuses), region);
                return rcb();
            }

            if (!listEventBuses.data.length) {
                helpers.addResult(results, 0, 'No Event buses found', region);
                return rcb();
            }
          
            listEventBuses.data.forEach(eventBus => {
                if (!eventBus.Arn) return;

                if (!eventBus.Policy) {
                    helpers.addResult(results, 0, 'Event bus does not use custom policy', region, eventBus.Arn);
                    return;
                }

                var statements = helpers.normalizePolicyDocument(eventBus.Policy);

                if (!statements || !statements.length) {
                    helpers.addResult(results, 0,
                        'Event bus policy does not have statements',
                        region, eventBus.Arn);
                    return;
                }

                var publicActions = [];

                for (var statement of statements) {
                    var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);
                    var principalEval = helpers.globalPrincipal(statement.Principal);
                    let scopedCondition;
                    if (statement.Condition) scopedCondition = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId);

                    if (!scopedCondition && principalEval && effectEval) {
                        if (statement.Action && typeof statement.Action === 'string') {
                            if (publicActions.indexOf(statement.Action) === -1) {
                                publicActions.push(statement.Action);
                            }
                        } else if (statement.Action && statement.Action.length) {
                            for (var a in statement.Action) {
                                if (publicActions.indexOf(statement.Action[a]) === -1) {
                                    publicActions.push(statement.Action[a]);
                                }
                            }
                        }
                    }
                }

                if (publicActions.length) {
                    helpers.addResult(results, 2,
                        'Event bus policy is exposed to everyone' ,
                        region, eventBus.Arn);
                } else {
                    helpers.addResult(results, 0,
                        'Event bus policy is not exposed to everyone',
                        region, eventBus.Arn);
                }
            });
         
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
