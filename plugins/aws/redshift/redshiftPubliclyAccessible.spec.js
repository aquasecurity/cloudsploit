var expect = require('chai').expect;
const redshiftPubliclyAccessible = require('./redshiftPubliclyAccessible');

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
        "PubliclyAccessible": true,
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

describe('redshiftPubliclyAccessible', function () {
    describe('run', function () {
        it('should PASS if Redshift cluster is not publicly accessible', function (done) {
            const cache = createCache([describeClusters[0]]);
            redshiftPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Redshift cluster is not publicly accessible');
                done();
            });
        });

        it('should WARN if Redshift cluster is publicly accessible', function (done) {
            const cache = createCache([describeClusters[1]]);
            redshiftPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Redshift cluster is publicly accessible');
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            redshiftPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Redshift clusters found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Redshift clusters', function (done) {
            const cache = createErrorCache();
            redshiftPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Redshift clusters');
                done();
            });
        });

        it('should not return anything if describe clusters response is not found', function (done) {
            const cache = createNullCache();
            redshiftPubliclyAccessible.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});