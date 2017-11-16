var async = require('async');
var helpers = require('../../helpers');

module.exports = {
   title: 'Detached EBS Volumes',
    category: 'EC2',
    description: 'Detects EBS volumes that are not attached to any instances',
    more_info: 'EBS volumes sometimes remain after an EC2 instance is \
                terminated. To avoid data exposure of the volume contents, \
                EBS volumes should be deleted if they are not attached to any \
                instances.',
    recommended_action: 'Delete EBS volumes that are not attached to instances',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html',
    apis: ['EC2:describeVolumes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.ec2, function(region, rcb){

            var describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);

            if (!describeVolumes) return rcb();

            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No volumes found', region);
                return rcb();
            }

            describeVolumes.data.forEach(function(vol){
                debugger;
                if (vol.State && vol.State == 'available'){
                    helpers.addResult(results, 2, 'Vol : ' + vol.VolumeId +
                        'has not being used',
                    region, 'arn:aws:ec2:::' + vol.VolumeId)
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
