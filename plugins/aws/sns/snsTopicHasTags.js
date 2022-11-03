var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Has Tags',
    category: 'SNS',
    domain: 'Application Integration',
    description: 'Ensure that Amazon SNS Topics have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify SNS topics and add tags.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-tags.html',
    apis: ['SNS:listTopics', 'SNS:listTagsForResource'],

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

            for (let topic of listTopics.data){
                if (!topic.TopicArn) continue;

                var listTagsForResource = helpers.addSource(cache, source,
                    ['sns', 'listTagsForResource', region, topic.TopicArn]);

                if (!listTagsForResource || listTagsForResource.err || !listTagsForResource.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic attributes: ' + helpers.addError(listTagsForResource),
                        region, topic.TopicArn);
                    continue;
                }
                if (!listTagsForResource.data.Tags || !listTagsForResource.data.Tags.length){
                    helpers.addResult(results, 2, 'SNS Topic does not have tags', region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0, 'SNS Topic has tags', region, topic.TopicArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
