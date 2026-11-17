var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EFS File System Required Tags',
    category: 'EFS',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensures that EFS file systems have the configured required tags with proper values.',
    more_info: 'Tags make it possible to find the owner, the data classification and the backup requirements of a resource. ' +
        'The required tags, and the allowed values of each tag, are defined in the settings of this plugin. Without required tags configured, no resource is evaluated.',
    link: 'https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html',
    recommended_action: 'Add the required tags with a proper value to the EFS file system.',
    apis: ['EFS:describeFileSystems'],
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
    realtime_triggers: ['efs:CreateFileSystem', 'efs:TagResource', 'efs:UntagResource', 'efs:DeleteFileSystem'],

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

        async.each(regions.efs, function(region, rcb) {
            var describeFileSystems = helpers.addSource(cache, source, ['efs', 'describeFileSystems', region]);

            if (!describeFileSystems) return rcb();

            if (describeFileSystems.err || !describeFileSystems.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
                return rcb();
            }

            var items = describeFileSystems.data;

            if (!items.length) {
                helpers.addResult(results, 0, 'No EFS file systems found', region);
                return rcb();
            }

            items.forEach(function(item) {
                var resource = item.FileSystemArn;
                helpers.addRequiredTagsResult(results, item.Tags, config, region, resource);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
