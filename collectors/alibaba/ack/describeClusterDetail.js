var ROAClient = require('@alicloud/pop-core').ROAClient;

var apiVersion = '2015-12-15';
var httpMethod = 'GET';
var uriPathClusters = '/api/v1/clusters';
var uriPathClusterDetail = '/clusters/';
var body = '{}';
var headers = {
    'Content-Type': 'application/json'
};
var requestOption = {};
var pageNumber = 1;

module.exports = function(AlibabaConfig, collection, region, callback) {
    let localConfig = { ...AlibabaConfig };
    localConfig['endpoint'] = `https://cs.${region}.aliyuncs.com`;
    localConfig['apiVersion'] = apiVersion;
    var client = new ROAClient(localConfig);

    collection.ack.describeClustersV1[region].data = [];

    var execute = function() {
        var queries = {
            'RegionId': region,
            'page_size': 50,
            'page_number': pageNumber
        };
        client.request(httpMethod, uriPathClusters, queries, body, headers, requestOption).then((res) => {
            callCB(null, res);
        }, (err) => {
            callCB(err);
        });
    };

    var callCB = function(err, data) {
        if (err) {
            collection.ack.describeClustersV1[region].err = err;
            return callback();
        }
        collection.ack.describeClustersV1[region].data = collection.ack.describeClustersV1[region].data.concat(data.clusters);
        if (data['page_info'] && data['page_info']['page_size'] &&
            data['page_info']['page_number'] && data['page_info']['total_count'] &&
            (data['page_info']['page_size'] * data['page_info']['page_number']) < data['page_info']['total_count']) {
            pageNumber += 1;
            execute();
        } else {
            executeDescribeClusterDetail();
        }
    };

    var executeDescribeClusterDetail = function() {
        var clusters = collection.ack.describeClustersV1[region].data;
        var totalClusters = clusters.length;
        var completedRequests = 0;
        var allRequestsCompleted = function() {
            callback();
        };

        var executeSingleClusterDetail = function(cluster, index) {
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
            executeSingleClusterDetail(clusters[i], i);
        }
    };

    execute();
};
