
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Exposed',
    category: 'SNS',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures SNS topics are not publicly accessible.',
    more_info: 'Allowing anonymous users to have access to your Amazon SNS topics can lead to unauthorized actions such as intercepting and receiving/publishing messages without permission. To avoid data leakage and unexpected costs , limit access to SNS topics by implementing the right permissions.',
    recommended_action: 'Identify any publicly accessible Amazon SNS topics and update their permissions in order to protect against attackers and unauthorized personnel.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html',
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
                var publicSnsTopic = false;

                for (var s in statements) {
                    var statement = statements[s];
                    
                    if (statement.Effect == 'Allow') {
                        if (helpers.globalPrincipal(statement.Principal, settings)) {
                            publicSnsTopic = true;
                            break;
                        }
                    }
                }
                
                if (publicSnsTopic) {
                    helpers.addResult(results, 2,
                        'The SNS topic is publicly exposed.', region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0, 'The SNS topic is not exposed.', region, topic.TopicArn);
                }
                
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
