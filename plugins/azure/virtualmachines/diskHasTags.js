var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Disk Has Tags',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that Azure virtual machine disks have tags.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify Disk and add tags.',
    apis: ['disks:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb) {

            var disks = helpers.addSource(cache, source, ['disks', 'list', location]);

            if (!disks) return rcb();

            if (disks.err || !disks.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine disk volumes: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disk volumes found', location);
                return rcb();
            }
            for (let disk of disks.data) {
                if (!disk.id) continue;

                if (disk.tags && Object.entries(disk.tags).length > 0){
                    helpers.addResult(results, 0, 'Disk has tags associated', location, disk.id);
                } else {
                    helpers.addResult(results, 2, 'Disk does not have tags associated', location, disk.id);
                }

            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};