var expect = require('chai').expect;
var redshiftAllowVersionUpgrade = require('./redshiftAllowVersionUpgrade');

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

const createCache = (clusters) => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
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

const createNullCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': null,
            }
        },
    };
};

describe('redshiftAllowVersionUpgrade', function () {
    describe('run', function () {
        it('should PASS if Redshift cluster is configured to allow version upgrade', function (done) {
            const cache = createCache([clusters[0]]);
            redshiftAllowVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Redshift cluster is not configured to allow version upgrade', function (done) {
            const cache = createCache([clusters[1]]);
            redshiftAllowVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            redshiftAllowVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Redshift clusters', function (done) {
            const cache = createErrorCache();
            redshiftAllowVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Redshift clusters response not found', function (done) {
            const cache = createNullCache();
            redshiftAllowVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
