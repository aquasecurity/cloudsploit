var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Policies',
    category: 'SNS',
    domain: 'Application Integration',
    description: 'Ensures SNS topics do not allow global send or subscribe.',
    more_info: 'SNS policies should not be configured to allow any AWS user to subscribe or send messages. This could result in data leakage or financial DDoS.',
    recommended_action: 'Adjust the topic policy to only allow authorized AWS users in known accounts to subscribe.',
    link: 'http://docs.aws.amazon.com/sns/latest/dg/AccessPolicyLanguage.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes', 'STS:getCallerIdentity'],
    settings: {
        sns_topic_policy_condition_keys: {
            name: 'SNS Topic Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount, aws:SourceArn' +
                'This setting assumes following rules:' +
                '1. As a best practice, "Deny" with "StringNotLike" and "Allow" with "StringLike" are used to prevent accidental privileged access' +
                '2. IAM condition keys which work with "Numeric" or "Date" operators are not used' +
                '3. Bool values are set to "true" with "Allow" and "false" with "Deny"',
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
            sns_topic_policy_condition_keys: settings.sns_topic_policy_condition_keys || this.settings.sns_topic_policy_condition_keys.default
        };
        config.sns_topic_policy_condition_keys = config.sns_topic_policy_condition_keys.replace(/\s/g, '');
        var allowedConditionKeys = config.sns_topic_policy_condition_keys.split(',');

        async.each(regions.sns, function(region, rcb){
            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SNS topics: ' + helpers.addError(listTopics), region);
                return rcb();
            }

            if (!listTopics.data.length) {
                helpers.addResult(results, 0, 'No SNS topics found', region);
                return rcb();
            }

            listTopics.data.forEach( topic => {
                if (!topic.TopicArn) return;
    
                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, topic.TopicArn]);
    
                if (!getTopicAttributes ||
                    (!getTopicAttributes.err && !getTopicAttributes.data)) return;
    
                if (getTopicAttributes.err || !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic for policy: ' + helpers.addError(getTopicAttributes),
                        region, topic.TopicArn);
                    return;
                }
    
                if (!getTopicAttributes.data.Attributes ||
                    !getTopicAttributes.data.Attributes.Policy) {
                    helpers.addResult(results, 3,
                        'The SNS topic does not have a policy attached.',
                        region, topic.TopicArn);
                    return;
                }
    
                var statements = helpers.normalizePolicyDocument(getTopicAttributes.data.Attributes.Policy);
    
                if (!statements || !statements.length) {
                    helpers.addResult(results, 0,
                        'The SNS Topic policy does not have trust relationship statements',
                        region, topic.TopicArn);
                    return;
                }
    
                var actions = [];
    
                for (var statement of statements) {
                    // Evaluates whether the effect of the statement is to "allow" access to the SNS
                    var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);

                    // Evaluates whether the principal is open to everyone/anonymous
                    var principalEval = helpers.globalPrincipal(statement.Principal);

                    // Evaluates whether condition is scoped or global
                    let scopedCondition;
                    if (statement.Condition) scopedCondition = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId);

                    if (!scopedCondition && principalEval && effectEval) {
                        if (statement.Action && typeof statement.Action === 'string') {
                            if (actions.indexOf(statement.Action) === -1) {
                                actions.push(statement.Action);
                            }
                        } else if (statement.Action && statement.Action.length) {
                            for (var a in statement.Action) {
                                if (actions.indexOf(statement.Action[a]) === -1) {
                                    actions.push(statement.Action[a]);
                                }
                            }
                        }
                    }
                }
    
                if (actions.length) {
                    helpers.addResult(results, 2,
                        'The SNS topic policy allows global access to the action(s): ' + actions,
                        region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0,
                        'The SNS topic policy does not allow global access.',
                        region, topic.TopicArn);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};