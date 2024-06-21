var ROAClient = require('@alicloud/pop-core').ROAClient;

var apiVersion = '2015-12-15';
var httpMethod = 'GET';
var uriPathClusterDetail = '/clusters/';
var body = '{}';
var headers = {
    'Content-Type': 'application/json'
};
var requestOption = {timeout: 30000};

module.exports = function(AlibabaConfig, collection, region, callback) {
    let localConfig = { ...AlibabaConfig };
    localConfig['endpoint'] = `https://cs.${region}.aliyuncs.com`;
    localConfig['apiVersion'] = apiVersion;
    var client = new ROAClient(localConfig);

    var clusters = collection.ack.describeClustersV1[region].data;
    var totalClusters = clusters.length;
    var completedRequests = 0;
    var allRequestsCompleted = function() {
        callback();
    };

    var executeSingleClusterDetail = function(cluster) {
        var clusterId = cluster.cluster_id;
        var uriPath = `${uriPathClusterDetail}${clusterId}`;
        client.request(httpMethod, uriPath, {}, body, headers, requestOption).then((res) => {             
            collection.ack.describeClusterDetail[region][clusterId] = {};
            collection.ack.describeClusterDetail[region][clusterId].data = res;
            completedRequests++;
            if (completedRequests === totalClusters) {
                allRequestsCompleted();
            }
        }, (err) => {
            collection.ack.describeClusterDetail[region][clusterId] = { err: err };
            completedRequests++;
            if (completedRequests === totalClusters) {
                allRequestsCompleted();
            }
        });
    };
    
    for (var i = 0; i < totalClusters; i++) {
        executeSingleClusterDetail(clusters[i]); 
    }
};
