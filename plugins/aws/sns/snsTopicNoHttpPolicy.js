var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic HTTP Protocol Restriction',
    category: 'SNS',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures SNS topics do not allow HTTP protocol.',
    more_info: 'SNS topics should be configured to restrict access to the HTTP protocol to prevent unauthorized send or subscribe operations.',
    recommended_action: 'Adjust the topic policy to only allow authorized AWS users in known accounts to send or subscribe via the HTTP protocol.',
    link: 'http://docs.aws.amazon.com/sns/latest/dg/AccessPolicyLanguage.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes'],
    realtime_triggers: ['sns:CreateTopic', 'sns:SetTopicAttributes','sns:DeleteTopic'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

                var hasHttpProtocolRestriction = false;

                function checkProtocol(protocol) {
                    protocol = protocol.toLowerCase();
                    if ((effect === 'Allow' && protocol === 'http') || (effect === 'Deny' && protocol === 'https')) {
                        return true;
                    }
                }
                for (var statement of statements) {
                    if (statement.Condition && statement.Condition.StringEquals) {
                        var protocolCondition = statement.Condition.StringEquals['SNS:Protocol'];
                        if (protocolCondition && protocolCondition.length) {
                            var effect = statement.Effect;
                            if (typeof protocolCondition === 'string') {
                                hasHttpProtocolRestriction = checkProtocol(protocolCondition);

                            } else if (Array.isArray(protocolCondition) && protocolCondition.length) {
                                for (var protocol of protocolCondition) {
                                    if (checkProtocol(protocol)) {
                                        hasHttpProtocolRestriction = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (hasHttpProtocolRestriction) break;
                    }
                }

                if (hasHttpProtocolRestriction) {
                    helpers.addResult(results, 2,
                        'The SNS topic policy allows unsecured access via HTTP protocol.',
                        region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0,
                        'The SNS topic policy does not allow unsecured access via HTTP protocol.',
                        region, topic.TopicArn);
                }

            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
