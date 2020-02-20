var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Volume Groups Restorable',
    category: 'Block Storage',
    description: 'Ensures volume groups can be restored to a recent point.',
    more_info: 'Enabling volume groups backups ensures that the volume group can be restored following in the event of data loss.',
    recommended_action: 'Ensure volume groups can be restored to a recent point.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm',
    apis: ['volumeGroup:list','volumeGroupBackup:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.volumeGroup, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var volumeGroups = helpers.addSource(cache, source,
                    ['volumeGroup', 'list', region]);

                if (!volumeGroups) return rcb();

                if ((volumeGroups.err && volumeGroups.err.length) || !volumeGroups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for volume groups: ' + helpers.addError(volumeGroups), region);
                    return rcb();
                }

                if (!volumeGroups.data.length) {
                    helpers.addResult(results, 0, 'No volume groups found', region);
                    return rcb();
                }


                var badVolumeGroups = [];
                volumeGroups.data.forEach(volumeGroup => {
                    badVolumeGroups.push(volumeGroup.id);
                });

                var volumeGroupBackups = helpers.addSource(cache, source,
                    ['volumeGroupBackup', 'list', region]);

                if (!volumeGroupBackups) return rcb();

                if ((volumeGroupBackups.err && volumeGroupBackups.err.length) || !volumeGroupBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for volume group backups: ' + helpers.addError(volumeGroupBackups), region);
                    return rcb();
                }

                volumeGroupBackups.data.forEach(volumeGroupBackup => {
                    var bootIdx = badVolumeGroups.indexOf(volumeGroupBackup.volumeGroupId);

                    if (volumeGroupBackup.lifecycleState &&
                        volumeGroupBackup.lifecycleState === 'TERMINATED') {
                        return;
                    } else if (bootIdx > -1) {
                        badVolumeGroups.splice(bootIdx, 1);
                    }
                });

                if (badVolumeGroups.length) {
                    var badVolumeGroupsStr = badVolumeGroups.join(', ');
                    helpers.addResult(results, 2,
                        `The following volume groups are not actively restorable: ${badVolumeGroupsStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All volume groups are restorable', region);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};