var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'Overlapping SecurityGroups',
    category: 'EC2',
    description: 'Determine if security group doesnt overlap with other',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Remove all overlapping security groups.',
    apis: ['EC2:describeInstances', 'EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }
            console.log(region);

            async.each(describeInstances.data, function(instance){
                if (instance.Instances[0].SecurityGroups.length > 1){
                    securityGroups = instance.Instances[0].SecurityGroups
                    for (sg of securityGroups) {
                        var describeSecurityGroups = helpers.addSource(cache, source,
                    ['ec2', 'describeSecurityGroups', region, sg.GroupId]);
                        debugger;


                        // it is giving null here
                        // can you please check why it is not calling
                        // describeSecurityGroups defined  in collectors
                    }

                }

            });

            // var found = false;


            // if (!found) {
            //     helpers.addResult(results, 0, 'No Overlapping SecurityGroups found', region);
            // }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
