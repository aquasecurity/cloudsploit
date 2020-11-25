var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var eks = new AWS.EKS(AWSConfig);
    //var autoscaling = new AWS.AutoScaling(AWSConfig);

    async.eachLimit(collection.eks.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.eks.describeNodegroups[AWSConfig.region][cluster] = {};
        async.each(collection.eks.listNodegroups[AWSConfig.region][cluster].data, function(nodeGroup, cb){
            collection.eks.describeNodegroups[AWSConfig.region][cluster][nodeGroup] = {};
            // Check for the multiple subnets in that single VPC
            var params = {
                clusterName: cluster,
                nodegroupName: nodeGroup
            };

            eks.describeNodegroup(params, function(err, data) {
                if (err) {
                    collection.eks.describeNodegroups[AWSConfig.region][cluster][nodeGroup].err = err;
                }
                //var autoScalingGroupNames = [];
                collection.eks.describeNodegroups[AWSConfig.region][cluster][nodeGroup].data = data.nodegroup;
                // right now we are taking the maxSize to count the node. But if we decide to count the exact node count
                // we need to uncomment the below code.
                // collection.eks.describeNodegroups[AWSConfig.region][cluster][nodeGroup].data['nodecount'] = 0;
                // data.nodegroup.resources.autoScalingGroups.forEach( autoscalingGroup => {
                //     autoScalingGroupNames.push(autoscalingGroup.name);
                // });
                // var params = {
                //     'AutoScalingGroupNames':
                //         autoScalingGroupNames
                // };
                // console.log(params);
                // autoscaling.describeAutoScalingGroups(params, function(err, data1){
                //     if (err) console.log(err);
                //     data1.AutoScalingGroups.forEach(autoscalingGroup =>{
                //         collection.eks.describeNodegroups[AWSConfig.region][cluster][nodeGroup].data['nodecount'] +=
                //         autoscalingGroup.Instances.length;
                //     });
                //     cb();
                // });
                cb();
            });
        }, function(){
            setTimeout(function(){
                cb();
            }, 100);
        });
    }, function(){
        callback();
    });
};