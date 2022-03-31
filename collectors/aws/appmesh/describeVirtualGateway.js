var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var appmesh = new AWS.AppMesh(AWSConfig);

    if (!collection.appmesh ||
        !collection.appmesh.listMeshes ||
        !collection.appmesh.listMeshes[AWSConfig.region] ||
        !collection.appmesh.listMeshes[AWSConfig.region].data) return callback();
    async.eachLimit(collection.appmesh.listMeshes[AWSConfig.region].data, 5, function(mesh, cb){
     
        if (!mesh.meshName || !collection.appmesh ||
            !collection.appmesh.listVirtualGateways ||
            !collection.appmesh.listVirtualGateways[AWSConfig.region] ||
            !collection.appmesh.listVirtualGateways[AWSConfig.region][mesh.meshName] ||
            !collection.appmesh.listVirtualGateways[AWSConfig.region][mesh.meshName].data ||
            !collection.appmesh.listVirtualGateways[AWSConfig.region][mesh.meshName].data.virtualGateways ||
            !collection.appmesh.listVirtualGateways[AWSConfig.region][mesh.meshName].data.virtualGateways.length) {
            return cb();
        }

        async.eachLimit(collection.appmesh.listVirtualGateways[AWSConfig.region][mesh.meshName].data.virtualGateways, 3, function(gateway, pCb){
            collection.appmesh.describeVirtualGateway[AWSConfig.region][gateway.virtualGatewayName] = {};

            helpers.makeCustomCollectorCall(appmesh, 'describeVirtualGateway', {virtualGatewayName: gateway.virtualGatewayName,meshName: mesh.meshName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.appmesh.describeVirtualGateway[AWSConfig.region][gateway.virtualGatewayName].err = err;
                }

                collection.appmesh.describeVirtualGateway[AWSConfig.region][gateway.virtualGatewayName].data = data;
                pCb();
            });

        }, function() {
            cb();
        });
    }, function(){
        callback();
    });
};