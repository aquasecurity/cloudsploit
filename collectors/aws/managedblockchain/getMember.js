var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var managedblockchain = new AWS.ManagedBlockchain(AWSConfig);

    if (!collection.managedblockchain ||
        !collection.managedblockchain.listNetworks ||
        !collection.managedblockchain.listNetworks[AWSConfig.region] ||
        !collection.managedblockchain.listNetworks[AWSConfig.region].data) return callback();

    async.eachLimit(collection.managedblockchain.listNetworks[AWSConfig.region].data, 3, function(network, cb){
        if (!network.Id || !collection.managedblockchain ||
            !collection.managedblockchain.listMembers ||
            !collection.managedblockchain.listMembers[AWSConfig.region] ||
            !collection.managedblockchain.listMembers[AWSConfig.region][network.Id] ||
            !collection.managedblockchain.listMembers[AWSConfig.region][network.Id].data ||
            !collection.managedblockchain.listMembers[AWSConfig.region][network.Id].data.Members) {
            return cb();
        }

        async.eachLimit(collection.managedblockchain.listMembers[AWSConfig.region][network.Id].data.Members, 5, function(member, mcb){
            collection.managedblockchain.getMember[AWSConfig.region][member.Id] = {};

            helpers.makeCustomCollectorCall(managedblockchain, 'getMember', {MemberId: member.Id,NetworkId: network.Id}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.managedblockchain.getMember[AWSConfig.region][member.Id].err = err;
                }

                collection.managedblockchain.getMember[AWSConfig.region][member.Id].data = data;
                mcb();
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