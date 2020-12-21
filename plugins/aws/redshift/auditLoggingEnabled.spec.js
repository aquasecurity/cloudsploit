var expect = require('chai').expect;
var auditLoggingEnabled = require('./auditLoggingEnabled');

const clusters = [
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
          "Address": "redshift-cluster-1.cks44thktt7l.us-east-1.redshift.amazonaws.com",
          "Port": 5439
        },
        "ClusterCreateTime": "2020-10-17T09:20:56.400Z",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [
          {
            "VpcSecurityGroupId": "sg-aa941691",
            "Status": "active"
          }
        ],
        "ClusterParameterGroups": [
          {
            "ParameterGroupName": "default.redshift-1.0",
            "ParameterApplyStatus": "in-sync",
            "ClusterParameterStatusList": []
          }
        ],
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "ClusterNodes": [
          {
            "NodeRole": "SHARED",
            "PrivateIPAddress": "172.31.1.36",
            "PublicIPAddress": "54.224.166.110"
          }
        ],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-10-17T19:00:00.000Z"
    },
    {
        "ClusterIdentifier": "redshift-cluster-2",
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
          "Address": "redshift-cluster-1.dwdfwe32ed23.us-east-1.redshift.amazonaws.com",
          "Port": 5439
        },
        "ClusterCreateTime": "2020-10-17T09:20:56.400Z",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [
          {
            "VpcSecurityGroupId": "sg-aa941691",
            "Status": "active"
          }
        ],
        "ClusterParameterGroups": [
          {
            "ParameterGroupName": "default.redshift-1.0",
            "ParameterApplyStatus": "in-sync",
            "ClusterParameterStatusList": []
          }
        ],
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": false,
        "NumberOfNodes": 1,
        "ClusterNodes": [
          {
            "NodeRole": "SHARED",
            "PrivateIPAddress": "172.31.1.36",
            "PublicIPAddress": "54.224.166.110"
          }
        ],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-10-17T19:00:00.000Z"
    }
];

const describeLoggingStatus = [
    {
        ResponseMetadata: { RequestId: '69c40fc7-0778-44b7-bec4-152e13890212' },
        LoggingEnabled: true,
        BucketName: 'test-rs-audit-logging',
        S3KeyPrefix: ''
    },
    {
        ResponseMetadata: { RequestId: '79291e75-f0e6-4813-b932-9a45683ebf08' },
        LoggingEnabled: false
    }
];

const createCache = (clusters, loggingStatus) => {
    var clusterIdentifier = (clusters && clusters.length) ? clusters[0].ClusterIdentifier : null;
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                }
            },
            describeLoggingStatus: {
                'us-east-1': {
                    [clusterIdentifier]: {
                        data: loggingStatus
                    }
                }
            }
        },
    }
};

const createErrorCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing Redshift clusters'
                    },
                },
            }
        }
    };
};

const createLoggingErrorCache = (clusters) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing Redshift clusters'
                    },
                }
            },
            describeLoggingStatus: {
                'us-east-1': {
                    [clusters[0].ClusterIdentifier]: {
                        err: {
                            message: 'error describing logging status'
                        }
                    }
                }
            }
        }
    };
}

const createNullCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': null,
            }
        },
    };
};

describe('auditLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if Redshift cluster is has audit logging enabled', function (done) {
            const cache = createCache([clusters[0]], describeLoggingStatus[0]);
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Redshift cluster does not have audit logging enabled', function (done) {
            const cache = createCache([clusters[1]], describeLoggingStatus[1]);
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Redshift clusters', function (done) {
            const cache = createErrorCache();
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query cluster logging status', function (done) {
            const cache = createLoggingErrorCache([clusters[0]]);
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Redshift clusters response not found', function (done) {
            const cache = createNullCache();
            auditLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
