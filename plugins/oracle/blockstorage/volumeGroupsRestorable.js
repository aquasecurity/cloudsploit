var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Volume Groups Restorable',
    category: 'Block Storage',
    description: 'Determine if Volume Groups can be restored to a recent point.',
    more_info: 'Enabling Volume Groups backups ensures that the volume group can be restored following in the event of data loss.',
    recommended_action: '1. Enter the Volume Groups Service. 2. Select the Volume Group in question. 3. Select the backups blade on the lower left side. 4. Create a backup.',
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
                        'Unable to query for Volume Groups: ' + helpers.addError(volumeGroups), region);
                    return rcb();
                };

                if (!volumeGroups.data.length) {
                    helpers.addResult(results, 0, 'No Volume Groups present', region);
                    return rcb();
                };


                var myVolumeGroups = [];
                volumeGroups.data.forEach(volumeGroup => {
                    myVolumeGroups.push(volumeGroup.id);
                });

                var volumeGroupBackups = helpers.addSource(cache, source,
                    ['volumeGroupBackup', 'list', region]);

                if (!volumeGroupBackups) return rcb();

                if ((volumeGroupBackups.err && volumeGroupBackups.err.length) || !volumeGroupBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Volume Group Backups: ' + helpers.addError(volumeGroupBackups), region);
                    return rcb();
                };

                volumeGroupBackups.data.forEach(volumeGroupBackup => {
                    var bootIdx = myVolumeGroups.indexOf(volumeGroupBackup.volumeGroupId)
                    if (volumeGroupBackup.lifecycleState &&
                        volumeGroupBackup.lifecycleState == 'TERMINATED') {
                        return
                    } else if (bootIdx > -1) {
                        myVolumeGroups.splice(bootIdx, 1);
                    };
                });

                if (myVolumeGroups.length) {
                    var myVolumeGroupsStr = myVolumeGroups.join(', ');
                    helpers.addResult(results, 2,
                        `The following Volume Groups are not actively restorable: ${myVolumeGroupsStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Volume Groups are restorable', region);
                };
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};