var expect = require('chai').expect;
const redshiftEncryptionEnabled = require('./redshiftEncryptionEnabled');

const describeClusters = [
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "ds2.xlarge",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": false
    },
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "ds2.xlarge",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": true
    }
];


const createCache = (clusters) => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing redshift clusters'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('redshiftEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if Redshift cluster is encrypted', function (done) {
            const cache = createCache([describeClusters[1]]);
            redshiftEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Redshift cluster is encrypted');
                done();
            });
        });

        it('should WARN if Redshift cluster is not encrypted', function (done) {
            const cache = createCache([describeClusters[0]]);
            redshiftEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Redshift cluster is not encrypted');
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            redshiftEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Redshift clusters found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Redshift clusters', function (done) {
            const cache = createErrorCache();
            redshiftEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Redshift clusters');
                done();
            });
        });

        it('should not return anything if describe clusters response is not found', function (done) {
            const cache = createNullCache();
            redshiftEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});