var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Subnet Group Required Tags',
    category: 'Redshift',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that Redshift subnet groups have the configured required tags with proper values.',
    more_info: 'Tags make it possible to find the owner, the data classification and the backup requirements of a resource. ' +
        'The required tags, and the allowed values of each tag, are defined in the settings of this plugin. Without required tags configured, no resource is evaluated.',
    link: 'https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html',
    recommended_action: 'Add the required tags with a proper value to the Redshift subnet group.',
    apis: ['Redshift:describeClusterSubnetGroups', 'STS:getCallerIdentity'],
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
    realtime_triggers: ['redshift:CreateClusterSubnetGroup', 'redshift:CreateTags', 'redshift:DeleteTags', 'redshift:DeleteClusterSubnetGroup'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config;
        try {
            config = helpers.getRequiredTagsConfig(settings, this.settings);
        } catch (e) {
            helpers.addResult(results, 3, 'The setting required_tags is not valid JSON: ' + e.message);
            return callback(null, results, source);
        }

        async.each(regions.redshift, function(region, rcb) {
            var describeClusterSubnetGroups = helpers.addSource(cache, source, ['redshift', 'describeClusterSubnetGroups', region]);

            if (!describeClusterSubnetGroups) return rcb();

            if (describeClusterSubnetGroups.err || !describeClusterSubnetGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Redshift subnet groups: ' + helpers.addError(describeClusterSubnetGroups), region);
                return rcb();
            }

            var items = describeClusterSubnetGroups.data;

            if (!items.length) {
                helpers.addResult(results, 0, 'No Redshift subnet groups found', region);
                return rcb();
            }

            items.forEach(function(item) {
                var resource = 'arn:' + awsOrGov + ':redshift:' + region + ':' + accountId + ':subnetgroup:' + item.ClusterSubnetGroupName;
                helpers.addRequiredTagsResult(results, item.Tags, config, region, resource);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
