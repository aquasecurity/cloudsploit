var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EFS Has Tags',
    category: 'EFS',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensure that AWS EFS file systems have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/efs/latest/ug/manage-fs-tags.html',
    recommended_action: 'Modify EFS file systems to add tags.',
    apis: ['EFS:describeFileSystems'],
    realtime_triggers: ['efs:CreateFileSystem', 'efs:TagResource', 'efs:UnTagResource','efs:DeleteFileSystem'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.efs, function(region, rcb) {
            var describeFileSystems = helpers.addSource(cache, source,
                ['efs', 'describeFileSystems', region]);

            if (!describeFileSystems) return rcb();

            if (describeFileSystems.err || !describeFileSystems.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
                return rcb();
            }

            if (!describeFileSystems.data.length){
                helpers.addResult(results, 0, 'No EFS file systems present', region);
                return rcb();
            }

            for (var efs of describeFileSystems.data) {
                const { FileSystemArn, Tags} = efs;

                if (!Tags.length){
                    helpers.addResult(results, 2, 'EFS file system does not have tags associated', region, FileSystemArn);
                } else {
                    helpers.addResult(results, 0, 'EFS file system has tags', region, FileSystemArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
