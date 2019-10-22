var assert = require('assert');
var expect = require('chai').expect;
var rds = require('./rdsMultiAz');

const createCache = (err, data) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('rdsMultiAz', function () {
    describe('run', function () {
        it('should give passing result if no RDS instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No RDS instances found')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            rds.run(cache, {}, callback);
        })

        it('should give passing result if no Aurora or DocDB RDS instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(3)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                expect(results[2].status).to.equal(0)
                expect(results[0].message).to.include('RDS Aurora instances are multi-AZ')
                expect(results[1].message).to.include('RDS Aurora instances are multi-AZ')
                expect(results[2].message).to.include('RDS DocDB instances multi-AZ property')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        Engine: 'aurora',
                        MultiAZ: true,
                        DBInstanceArn: 'arn:rds:example'
                    },
                    {
                        Engine: 'aurora-postgresql',
                        MultiAZ: true,
                        DBInstanceArn: 'arn:rds:example'
                    },
                    {
                        Engine: 'docdb',
                        MultiAZ: false,
                        DBInstanceArn: 'arn:rds:example'
                    }
                ]
            );

            rds.run(cache, {}, callback);
        })

        it('should give passing result if multi-AZ RDS instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('RDS instance has multi-AZ enabled')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        Engine: 'mysql',
                        MultiAZ: true,
                        DBInstanceArn: 'arn:rds:example'
                    }
                ]
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if non-multi-AZ RDS instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('RDS instance does not have multi-AZ enabled')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        Engine: 'mysql',
                        MultiAZ: false,
                        DBInstanceArn: 'arn:rds:example'
                    }
                ]
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if non-multi-AZ RDS read replicas are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('RDS instance does not have multi-AZ enabled')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        Engine: 'mysql',
                        MultiAZ: false,
                        DBInstanceArn: 'arn:rds:example',
                        ReadReplicaSourceDBInstanceIdentifier: 'mysource'
                    }
                ]
            );

            rds.run(cache, {rds_multi_az_ignore_replicas: 'false'}, callback);
        })

        it('should give passing result if non-multi-AZ RDS read replicas are found with override', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('RDS instance does not have multi-AZ enabled but is a read replica')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        Engine: 'mysql',
                        MultiAZ: false,
                        DBInstanceArn: 'arn:rds:example',
                        ReadReplicaSourceDBInstanceIdentifier: 'mysource'
                    }
                ]
            );

            rds.run(cache, {rds_multi_az_ignore_replicas: 'true'}, callback);
        })
    })
})