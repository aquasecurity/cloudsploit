var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM OS Disk Encryption',
    category: 'Virtual Machines',
    description: 'Ensure that VM OS Disk Encryption is enabled',
    more_info: "Encrypting your IaaS VM OS disk (boot volume) ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.",
    recommended_action: 'Enable VM OS Disk Encryption on all virtual machines',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-disk-encryption',
    apis: ['disks:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'Enabling encryption of VM OS data helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
             'Encryption should be enabled for all VM OS disks storing this ' +
             'type of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.disks, function(location, rcb){

            var disks = helpers.addSource(cache, source, ['disks', 'list', location]);

            if (!disks) return rcb();

            if (disks.err || !disks.data) {
                helpers.addResult(results, 3,
                    'Unable to query Disks: ' + helpers.addError(disks), location);
                return rcb();
            }
            if (!disks.data.length) {
                helpers.addResult(results, 0, 'No existing disks', location);
            } else {
                var reg = 0;
                for(i in disks.data){
                    if (disks.data[i].name &&
                        disks.data[i].name.length>0
                    ) {
                        var diskType = disks.data[i].name.split("_")[1];
                        if (diskType === "OsDisk") {
                            if (!disks.data[i].encryptionSettings ||
                                (disks.data[i].encryptionSettings &&
                                    !disks.data[i].encryptionSettings.enabled)
                            ) {
                                helpers.addResult(results, 2, "OS disk encryption is not enabled", location, disks.data[i].id);
                                reg++;
                            }
                        }
                    }
                }
                if(!reg){
                    helpers.addResult(results, 0, "OS disk encryption is enabled", location);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}