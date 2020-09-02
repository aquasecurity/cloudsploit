var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused EBS Volumes',
    category: 'EC2',
    description: 'Ensures EBS volumes are in use and attached to EC2 instances',
    more_info: 'EBS volumes should be deleted if the parent instance has been deleted to prevent accidental exposure of data',
    recommended_action: 'Delete the unassociated EBS volume',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html',
    apis: ['EC2:describeVolumes', 'EC2:describeInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb) {
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            var describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);

            if (!describeInstances || !describeVolumes) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EC2 Instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EBS Volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS Volumes found', region);
                return rcb();
            }

            var usedEbsVolumes = [];
            if(describeInstances.data.length) {
                describeInstances.data.forEach(function(instances) {
                    instances.Instances.forEach(function(instance) {
                        if(instance.BlockDeviceMappings && instance.BlockDeviceMappings.length) {
                            instance.BlockDeviceMappings.forEach(function(ebsMapping) {
                                usedEbsVolumes.push(ebsMapping.Ebs.VolumeId);
                            });
                        }
                    });
                });
            }

            var unusedEbsVolumeFound = false;
            describeVolumes.data.forEach(function(volume) {
                if (volume.VolumeId) {
                    if(!usedEbsVolumes.includes(volume.VolumeId)) {
                        unusedEbsVolumeFound = true;
                        helpers.addResult(results, 2, 'EBS Volume is not attached to any EC2 instance', region, volume.VolumeId);
                    }
                }
            });

            if(!unusedEbsVolumeFound){
                helpers.addResult(results, 0, 'All EBS Volumes are attached to EC2 instances', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};