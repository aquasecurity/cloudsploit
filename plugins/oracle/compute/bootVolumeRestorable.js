var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Restorable',
    category: 'Compute',
    description: 'Ensures boot volumes can be restored to a recent point.',
    more_info: 'Having an active backup ensures that the boot volumes can be restored in the event of a compromised system or hardware failure.',
    recommended_action: 'Ensures boot volumes can be restored to a recent point.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolume:list','bootVolumeBackup:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bootVolume, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var bootVolumes = helpers.addSource(cache, source,
                    ['bootVolume', 'list', region]);

                if (!bootVolumes) return rcb();

                if ((bootVolumes.err && bootVolumes.err.length) || !bootVolumes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume attachments: ' + helpers.addError(bootVolumes), region);
                    return rcb();
                }


                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 0, 'No boot volumes found', region);
                    return rcb();
                }


                var badBootVolumes = [];
                bootVolumes.data.forEach(bootVolume => {
                    badBootVolumes.push(bootVolume.id);
                });

                var bootVolumeBackups = helpers.addSource(cache, source,
                    ['bootVolumeBackup', 'list', region]);

                if (!bootVolumeBackups) return rcb();

                if ((bootVolumeBackups.err && bootVolumeBackups.err.length) || !bootVolumeBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume backups: ' + helpers.addError(bootVolumeBackups), region);
                    return rcb();
                }

                bootVolumeBackups.data.forEach(bootVolumeBackup => {
                    if (badBootVolumes.indexOf(bootVolumeBackup.bootVolumeId) > -1) {
                        badBootVolumes.splice(badBootVolumes.indexOf(bootVolumeBackup.bootVolumeId), 1);
                    }
                });

                if (badBootVolumes.length) {
                    var badBootVolumesStr = badBootVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following boot volumes are not actively restorable: ${badBootVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All boot volumes are actively restorable', region);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
