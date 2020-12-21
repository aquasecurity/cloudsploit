const expect = require('chai').expect;
const userActivityLoggingEnabled = require('./userActivityLoggingEnabled');

const clusters = [
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "dc2.large",
        "ClusterStatus": "creating",
        "ClusterAvailabilityStatus": "Modifying",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
            {
                "ParameterGroupName": "default.redshift-1.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "ClusterSubnetGroupName": "default",
        "VpcId": "vpc-99de2fe4",
        "PendingModifiedValues": {
            "MasterUserPassword": "****"
        },
        "ClusterVersion": "1.0"
    },
    {
        "ClusterIdentifier": "redshift-cluster-2",
        "NodeType": "dc2.large",
        "ClusterStatus": "creating",
        "ClusterAvailabilityStatus": "Modifying",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
            {
                "ParameterGroupName": "test-124",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "ClusterSubnetGroupName": "default",
        "VpcId": "vpc-99de2fe4",
        "PendingModifiedValues": {
            "MasterUserPassword": "****"
        },
        "ClusterVersion": "1.0"
    },
    {
        "ClusterIdentifier": "redshift-cluster-3",
        "NodeType": "dc2.large",
        "ClusterStatus": "creating",
        "ClusterAvailabilityStatus": "Modifying",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
            {
                "ParameterGroupName": "test1-124",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "ClusterSubnetGroupName": "default",
        "VpcId": "vpc-99de2fe4",
        "PendingModifiedValues": {
            "MasterUserPassword": "****"
        },
        "ClusterVersion": "1.0"
    }
];

const parameterGroups = [
    {
        "ParameterGroupName": "default.redshift-1.0",
        "ParameterGroupFamily": "redshift-1.0",
        "Description": "Default parameter group for redshift-1.0",
        "Tags": []
    },
    {
        "ParameterGroupName": "test-124",
        "ParameterGroupFamily": "redshift-1.0",
        "Description": "Cloudsploit plugin development",
        "Tags": []
    },
    {
        "ParameterGroupName": "test1-124",
        "ParameterGroupFamily": "redshift-1.0",
        "Description": "Cloudsploit plugin development",
        "Tags": []
    }
];

const parameters = [
    {
        "Parameters": [
            {
                "ParameterName": "enable_user_activity_logging",
                "ParameterValue": "false",
                "Description": "parameter for audit logging purpose",
                "Source": "user",
                "DataType": "boolean",
                "AllowedValues": "true,false",
                "ApplyType": "static",
                "IsModifiable": true
            }
        ]
    },
    {
        "Parameters": [
            {
                "ParameterName": "enable_user_activity_logging",
                "ParameterValue": "true",
                "Description": "parameter for audit logging purpose",
                "Source": "user",
                "DataType": "boolean",
                "AllowedValues": "true,false",
                "ApplyType": "static",
                "IsModifiable": true
            }
        ]
    }
];

const createCache = (clusters, parameterGroups, parameters) => {
    var parameterGroupName = (clusters && clusters.length) ? clusters[0].ClusterParameterGroups[0].ParameterGroupName : null;
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
            describeClusterParameterGroups: {
                'us-east-1': {
                        data: parameterGroups
                },
            },
            describeClusterParameters: {
                'us-east-1': {
                    [parameterGroupName]: {
                        data: parameters
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

const createNullCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': null,
            }
        },
    };
};

describe('userActivityLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if parameter group associated with Redshift cluster has user activity logging enabled', function (done) {
            const cache = createCache([clusters[1]], [parameterGroups[1]], parameters[1]);
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if parameter group associated with Redshift cluster does not have user activity logging enabled', function (done) {
            const cache = createCache([clusters[2]], [parameterGroups[2]], parameters[0]);
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Redshift cluster is using default parameter group', function (done) {
            const cache = createCache([clusters[0]], [parameterGroups[0]], parameters[0]);
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query parameter group', function (done) {
            const cache = createCache([clusters[2]], [parameterGroups[2]]);
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query for Redshift clusters', function (done) {
            const cache = createErrorCache();
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Redshift clusters response not found', function (done) {
            const cache = createNullCache();
            userActivityLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});