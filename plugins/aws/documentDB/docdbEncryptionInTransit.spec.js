var expect = require('chai').expect;
var docdbEncryptionInTransit = require('./docdbEncryptionInTransit');

const describeDBClusters = [
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 7,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
        DBClusterIdentifier: 'docdb-2021-11-10-10-16-10',
        DBClusterParameterGroup: 'custom-docdb-param-group',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'docdb',
        EngineVersion: '4.0.0'
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 7,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112223:cluster:docdb-2021-11-10-10-16-11',
        DBClusterIdentifier: 'docdb-2021-11-10-10-16-11',
        DBClusterParameterGroup: 'custom-docdb-param-group-disabled',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'docdb',
        EngineVersion: '4.0.0'
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 7,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112224:cluster:docdb-2021-11-10-10-16-12',
        DBClusterIdentifier: 'docdb-2021-11-10-10-16-12',
        DBClusterParameterGroup: 'default.docdb4.0',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'docdb',
        EngineVersion: '4.0.0'
    },
    {
        AvailabilityZones: [],
        BackupRetentionPeriod: 7,
        DBClusterArn: 'arn:aws:rds:us-east-1:000011112225:cluster:docdb-2021-11-10-10-16-13',
        DBClusterIdentifier: 'docdb-2021-11-10-10-16-13',
        DBSubnetGroup: 'default-vpc-99de2fe4',
        Status: 'available',
        Engine: 'docdb',
        EngineVersion: '4.0.0'
    }
];

const clusterParameters = {
    'custom-docdb-param-group': {
        Parameters: [
            {
                ParameterName: 'tls',
                ParameterValue: 'enabled',
                Description: 'Enable TLS encryption',
                Source: 'user',
                ApplyType: 'static',
                DataType: 'string',
                AllowedValues: 'enabled,disabled',
                IsModifiable: true
            }
        ]
    },
    'custom-docdb-param-group-disabled': {
        Parameters: [
            {
                ParameterName: 'tls',
                ParameterValue: 'disabled',
                Description: 'Enable TLS encryption',
                Source: 'user',
                ApplyType: 'static',
                DataType: 'string',
                AllowedValues: 'enabled,disabled',
                IsModifiable: true
            }
        ]
    }
};

const createCache = (clusters, clustersErr, parameters, parametersErr) => {
    var cache = {
        docdb: {
            describeDBClusters: {
                'us-east-1': {
                    err: clustersErr,
                    data: clusters
                },
            },
        }
    };

    if (parameters) {
        cache.docdb = cache.docdb || {};
        cache.docdb.describeDBClusterParameters = {
            'us-east-1': {}
        };
        for (var groupName in parameters) {
            cache.docdb.describeDBClusterParameters['us-east-1'][groupName] = {
                err: parametersErr,
                data: parameters[groupName]
            };
        }
    }

    return cache;
};

describe('docdbEncryptionInTransit', function () {
    describe('run', function () {
        it('should PASS if DocumentDB cluster has TLS enabled in custom parameter group', function (done) {
            const cache = createCache([describeDBClusters[0]], null, clusterParameters);
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has TLS encryption in transit enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DocumentDB cluster has TLS disabled in parameter group', function (done) {
            const cache = createCache([describeDBClusters[1]], null, clusterParameters);
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have TLS encryption in transit enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DocumentDB cluster uses default parameter group', function (done) {
            const cache = createCache([describeDBClusters[2]], null, {
                'default.docdb4.0': {
                    Parameters: [
                        {
                            ParameterName: 'tls',
                            ParameterValue: 'disabled',
                            Description: 'Enable TLS encryption',
                            Source: 'system',
                            ApplyType: 'static',
                            DataType: 'string',
                            AllowedValues: 'enabled,disabled',
                            IsModifiable: false
                        }
                    ]
                }
            });
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have TLS encryption in transit enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if DocumentDB cluster has no parameter group', function (done) {
            const cache = createCache([describeDBClusters[3]], null);
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have a parameter group associated');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no DocumentDB clusters found', function (done) {
            const cache = createCache([]);
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DocumentDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DocumentDB clusters', function (done) {
            const cache = createCache(null, { message: "Unable to list DocumentDB Clusters" });
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list DocumentDB clusters:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query cluster parameters', function (done) {
            const cache = createCache([describeDBClusters[0]], null, null, { message: "Unable to query parameters" });
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query cluster parameters');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if cluster parameters data is null', function (done) {
            const cache = createCache([describeDBClusters[0]], null, {
                'custom-docdb-param-group': {
                    Parameters: null
                }
            });
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have TLS encryption in transit enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if cluster parameters array is empty', function (done) {
            const cache = createCache([describeDBClusters[0]], null, {
                'custom-docdb-param-group': {
                    Parameters: []
                }
            });
            docdbEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have TLS encryption in transit enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
