var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Backup Enabled',
    category: 'Compute',
    description: 'Determine if Boot Volumes have a backup policy.',
    more_info: 'Enabling a Boot Volume backup policy ensures that the boot volumes can be restored in the event of a compromised system or hardware failure.',
    recommended_action: '1. Enter the Boot Volume Service. 2. Select the Boot Volume in question. 3. Select Assign next to Backup Policy. 4. Select the best policy for your services.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolume:list','volumeBackupPolicyAssignment:bootVolume'],

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
                };

                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 0, 'No Boot Volumes present', region);
                    return rcb();
                };


                var myBootVolumes = [];
                bootVolumes.data.forEach(bootVolume => {
                    myBootVolumes.push(bootVolume.id);
                });

                var bootVolumeBackupPolicies = helpers.addSource(cache, source,
                    ['volumeBackupPolicyAssignment', 'bootVolume', region]);

                if (!bootVolumeBackupPolicies) return rcb();

                if ((bootVolumeBackupPolicies.err && bootVolumeBackupPolicies.err.length) || !bootVolumeBackupPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Boot Volume Backups: ' + helpers.addError(bootVolumeBackupPolicies), region);
                    return rcb();
                };

                bootVolumeBackupPolicies.data.forEach(bootVolumeBackupPolicy => {
                    var bootIdx = myBootVolumes.indexOf(bootVolumeBackupPolicy.bootVolumeId)

                    if (bootIdx > -1) {
                        myBootVolumes.splice(bootIdx, 1);
                    };
                });

                if (myBootVolumes.length) {
                    var myBootVolumesStr = myBootVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following Boot Volumes do not have a backup policy: ${myBootVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Boot Volumes have a backup policy', region);
                };
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};