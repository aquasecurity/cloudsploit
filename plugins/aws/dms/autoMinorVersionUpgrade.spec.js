var expect = require('chai').expect;
var autoMinorVersionUpgrade = require('./autoMinorVersionUpgrade');

const describeReplicationInstances = [
    {
        "ReplicationInstanceIdentifier": "mine1",
        "ReplicationInstanceClass": "dms.t3.micro",
        "ReplicationInstanceStatus": "creating",
        "AutoMinorVersionUpgrade": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/d691a16e-cc12-4611-8145-93f92d7d6eaf",
        "ReplicationInstanceArn": "arn:aws:dms:us-east-1:000011112222:rep:XR6L5CYX66ALXX2GE3Y5E25G3LUW76KGZ5PUIEI",
        "PubliclyAccessible": true
    },
    {
        "ReplicationInstanceIdentifier": "mine1",
        "ReplicationInstanceClass": "dms.t3.micro",
        "ReplicationInstanceStatus": "creating",
        "AutoMinorVersionUpgrade": false,
        "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/d691a16e-cc12-4611-8145-93f92d7d6eaf",
        "ReplicationInstanceArn": "arn:aws:dms:us-east-1:000011112222:rep:XR6L5CYX66ALXX2GE3Y5E25G3LUW76KGZ5PUIEI",
        "PubliclyAccessible": true
    }
];

const createCache = (instances, instancesErr) => {
    return {
        dms: {
            describeReplicationInstances: {
                'us-east-1': {
                    err: instancesErr,
                    data: instances
                },
            },
        }
    };
};

describe('autoMinorVersionUpgrade', function () {
    describe('run', function () {
        it('should PASS if Replication instances have auto minor version upgrade enabled.', function (done) {
            const cache = createCache([describeReplicationInstances[0]]);
            autoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Replication instance has auto minor version upgrade enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Replication instances does not have auto minor version upgrade enabled.', function (done) {
            const cache = createCache([describeReplicationInstances[1]]);
            autoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Replication instance does not have auto minor version upgrade enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no DMS replication instances found', function (done) {
            const cache = createCache([]);
            autoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DMS replication instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DMS replication instances', function (done) {
            const cache = createCache(null,  { message: "Unable to list DMS replication instances" });
            autoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
