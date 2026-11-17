var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'KMS Key Required Tags',
    category: 'KMS',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures that customer managed KMS keys have the configured required tags with proper values.',
    more_info: 'Tags make it possible to find the owner, the data classification and the backup requirements of a resource. ' +
        'The required tags, and the allowed values of each tag, are defined in the settings of this plugin. Without required tags configured, no resource is evaluated.',
    link: 'https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html',
    recommended_action: 'Add the required tags with a proper value to the KMS key.',
    apis: ['KMS:listKeys', 'KMS:describeKey', 'KMS:listResourceTags'],
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
    realtime_triggers: ['kms:CreateKey', 'kms:TagResource', 'kms:UntagResource', 'kms:ScheduleKeyDeletion'],

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

        async.each(regions.kms, function(region, rcb) {
            var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to query for KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            if (!listKeys.data.length) {
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();
            }

            listKeys.data.forEach(function(key) {
                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        'Unable to describe KMS key: ' + helpers.addError(describeKey), region, key.KeyArn);
                    return;
                }

                if (describeKey.data.KeyMetadata.KeyManager === 'AWS') {
                    helpers.addResult(results, 0, 'Resource is out of scope, the key is managed by AWS', region, key.KeyArn);
                    return;
                }

                var listResourceTags = helpers.addSource(cache, source, ['kms', 'listResourceTags', region, key.KeyId]);

                if (!listResourceTags || listResourceTags.err || !listResourceTags.data) {
                    helpers.addResult(results, 3,
                        'Unable to query the tags of the KMS key: ' + helpers.addError(listResourceTags), region, key.KeyArn);
                    return;
                }

                helpers.addRequiredTagsResult(results, listResourceTags.data.Tags, config, region, key.KeyArn);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
