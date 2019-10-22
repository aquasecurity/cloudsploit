var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Restorable',
    category: 'Compute',
    description: 'Determine if Boot Volumes can be restored to a recent point.',
    more_info: 'Having an active backup ensures that the boot volumes can be restored in the event of a compromised system or hardware failure.',
    recommended_action: '1. Enter the Boot Volume Service. 2. Select the Boot Volume in question. 3. Select the Boot Volume Backups blade in the lower left corner. 4. Create a backup.',
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
                        'Unable to query for Boot Volume Attachments: ' + helpers.addError(bootVolumes), region);
                    return rcb();
                }
                ;

                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 0, 'No Boot Volumes present', region);
                    return rcb();
                };


                var myBootVolumes = [];
                bootVolumes.data.forEach(bootVolume => {
                    myBootVolumes.push(bootVolume.id);
                });

                var bootVolumeBackups = helpers.addSource(cache, source,
                    ['bootVolumeBackup', 'list', region]);

                if (!bootVolumeBackups) return rcb();

                if ((bootVolumeBackups.err && bootVolumeBackups.err.length) || !bootVolumeBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Boot Volume Backups: ' + helpers.addError(bootVolumeBackups), region);
                    return rcb();
                };

                bootVolumeBackups.data.forEach(bootVolumeBackup => {
                    var bootIdx = myBootVolumes.indexOf(bootVolumeBackup.bootVolumeId)

                    if (bootIdx > -1) {
                        myBootVolumes.splice(bootIdx, 1);
                    };
                });

                if (myBootVolumes.length) {
                    var myBootVolumesStr = myBootVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following Boot Volumes are not actively restorable: ${myBootVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Boot Volumes are actively restorable', region);
                };
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
