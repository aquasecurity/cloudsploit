var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volumes Recent Snapshots',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures that EBS volume has had a snapshot within the last 7 days',
    more_info: 'EBS volumes without recent snapshots may be at risk of data loss or recovery issues.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html',
    recommended_action: 'Create a new snapshot for EBS volume weekly.',
    apis: ['EC2:describeVolumes','EC2:describeSnapshots','STS:getCallerIdentity'],


    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);
            var describeSnapshots = helpers.addSource(cache, source,
                ['ec2', 'describeSnapshots', region]);    

            if (!describeVolumes) return rcb();

            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EBS volumes: ${helpers.addError(describeVolumes)}`, region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS Volumes found', region);
                return rcb();
            }

            if (!describeSnapshots || describeSnapshots.err || !describeSnapshots.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EBS Snapshots: ${helpers.addError(describeSnapshots)}`, region);
                return rcb();
            }

            let volumeSet = new Set();
      
            describeSnapshots.data.forEach(function(snapshot){
                if (snapshot.VolumeId) {
                    volumeSet.add(snapshot.VolumeId);
                }
            });

            describeVolumes.data.forEach(function(volume) {
                let resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;
                if (volume.VolumeId) {
                    if (volumeSet.has(volume.VolumeId)) {
                        var recentSnapshot = false;
                        var today = new Date();
                        describeSnapshots.data.forEach(function (snapshot) {
                           var snapshottime = snapshot.StartTime;
                           var difference = Math.floor((today -snapshot.StartTime) / (1000 * 60 * 60 * 24));

                            if (difference < 7)
                            {
                                recentSnapshot = true;
                            }
                            });

                        if(recentSnapshot)
                        {
                            helpers.addResult(results, 0, `EBS volume have a recent snapshot`, region,resource);
                        }else{
                             helpers.addResult(results, 2, `EBS volume does not have a recent snapshot`, region,resource);
                        }
                    }
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        }
       );
    },
};
