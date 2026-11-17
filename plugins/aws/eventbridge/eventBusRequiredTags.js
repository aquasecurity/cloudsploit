var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Event Bus Required Tags',
    category: 'EventBridge',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensures that EventBridge event buses have the configured required tags with proper values.',
    more_info: 'Tags make it possible to find the owner, the data classification and the backup requirements of a resource. ' +
        'The required tags, and the allowed values of each tag, are defined in the settings of this plugin. Without required tags configured, no resource is evaluated.',
    link: 'https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html',
    recommended_action: 'Add the required tags with a proper value to the EventBridge event bus.',
    apis: ['EventBridge:listEventBuses', 'ResourceGroupsTaggingAPI:getResources'],
    settings: {
        required_tags: {
            name: 'Required Tags',
            description: 'JSON object with the required tag keys and the comma separated allowed values of each tag, ' +
                'for example {"Owner":"*","Environment":"dev,test,prod"}. An asterisk as value accepts any non-empty value. ' +
                'When empty ({}), no tags are required.',
            regex: '^\\{.*\\}$',
            default: '{}'
        },
        required_tags_exempt_keys: {
            name: 'Required Tags Exempt Tag Keys',
            description: 'Comma separated list of tag keys. Resources that have one of these tag keys are not evaluated. When empty, every resource is evaluated.',
            regex: '^[^,]*(,[^,]+)*$',
            default: ''
        }
    },
    realtime_triggers: ['events:CreateEventBus', 'events:TagResource', 'events:UntagResource', 'events:DeleteEventBus'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config;
        try {
            config = helpers.getRequiredTagsConfig(settings, this.settings);
        } catch (e) {
            helpers.addResult(results, 3, 'The setting required_tags is not valid JSON: ' + e.message);
            return callback(null, results, source);
        }

        async.each(regions.eventbridge, function(region, rcb) {
            var listEventBuses = helpers.addSource(cache, source, ['eventbridge', 'listEventBuses', region]);

            if (!listEventBuses) return rcb();

            if (listEventBuses.err || !listEventBuses.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EventBridge event buses: ' + helpers.addError(listEventBuses), region);
                return rcb();
            }

            var items = listEventBuses.data;

            if (!items.length) {
                helpers.addResult(results, 0, 'No EventBridge event buses found', region);
                return rcb();
            }

            var getResources = helpers.addSource(cache, source, ['resourcegroupstaggingapi', 'getResources', region]);

            if (!getResources || getResources.err || !getResources.data) {
                helpers.addResult(results, 3,
                    'Unable to query the tags of the resources: ' + helpers.addError(getResources), region);
                return rcb();
            }

            // Resources that never had a tag are not returned by the tagging API
            var tagsByArn = {};
            getResources.data.forEach(function(resource) {
                tagsByArn[resource.ResourceARN] = resource.Tags;
            });

            items.forEach(function(item) {
                var resource = item.Arn;

                if (resource.endsWith('/default')) {
                    helpers.addResult(results, 0, 'The default event bus cannot be tagged, resource is out of scope', region, resource);
                    return;
                }

                helpers.addRequiredTagsResult(results, tagsByArn[resource] || [], config, region, resource);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
