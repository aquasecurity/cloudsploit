// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Detect EC2 Classic Instances',
    category: 'EC2',
    description: 'Ensures AWS VPC is being used for instances instead of EC2 Classic',
    more_info: 'VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.',
    link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html',
    recommended_action: 'Migrate instances from EC2 Classic to VPC',
    apis: ['EC2:describeInstances'],
    compliance: {
        hipaa: 'AWS VPC is the recommended location for processing of HIPAA-related ' +
                'data. All EC2 instances storing or processing HIPAA data should be ' +
                'launched in a VPC to avoid exposure to the public network.',
        pci: 'VPCs provide a firewall for compute resources that meets the network ' +
             'segmentation criteria for PCI. Ensure all instances are launched ' +
             'within a VPC to comply with isolation requirements.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
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

            var inVpc = 0;
            var notInVpc = 0;

            for (var i in describeInstances.data) {
                for (var j in describeInstances.data[i].Instances) {
                    // When the instance is shutting down or stopped, it no longer maintains
                    // the NetworkInterfaces property used to determine instance VPC placement
                    if (describeInstances.data[i].Instances[j].State &&
                        describeInstances.data[i].Instances[j].State.Name &&
                        describeInstances.data[i].Instances[j].State.Name !== 'running') continue;

                    if (!describeInstances.data[i].Instances[j].NetworkInterfaces || !describeInstances.data[i].Instances[j].NetworkInterfaces.length) {
                        // Network interfaces are only listed when the instance is in a VPC
                        // Not having interfaces indicates the instance is in classic
                        notInVpc+=1;
                    } else {
                        inVpc+=1;
                    }
                }
            }

            if (notInVpc) {
                helpers.addResult(results, 1,
                    'There are ' + notInVpc + ' instances in EC2-Classic', region);
            } else if (inVpc) {
                helpers.addResult(results, 0,
                    'There are ' + inVpc + ' instances in a VPC', region);
            } else {
                helpers.addResult(results, 0,
                    'No instances found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
