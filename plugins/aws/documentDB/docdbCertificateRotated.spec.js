var expect = require('chai').expect;
var docdbInstanceCertificateRotated = require('./docdbCertificateRotated');


const describeDBInstances = [
    {
        DBInstanceIdentifier: "docdb-2024-06-12-19-45-21",
        Engine: "docdb",
        DBInstanceStatus: "available",
        BackupRetentionPeriod: 1,
        MultiAZ: false,
        EngineVersion: "5.0.0",
        AutoMinorVersionUpgrade: true,
        ReadReplicaDBInstanceIdentifiers: [
        ],
        ReadReplicaDBClusterIdentifiers: [
        ],
        LicenseModel: "na",
        OptionGroupMemberships: [
            {
            OptionGroupName: "default:docdb-5-0",
            Status: "in-sync",
            },
        ],
        PubliclyAccessible: false,
        StatusInfos: [
        ],
        StorageType: "standard",
        DbInstancePort: 0,
        DBClusterIdentifier: "docdb-2024-06-12-19-45-21",
        StorageEncrypted: false,
        DbiResourceId: "db-QNKFC3466G5XP6NLPXHSZDY5ZQ",
        CACertificateIdentifier: "rds-ca-2019",
        DomainMemberships: [
        ],
        CopyTagsToSnapshot: false,
        MonitoringInterval: 0,
        PromotionTier: 1,
        DBInstanceArn: "arn:aws:rds:us-east-1:1234123412:db:docdb-2024-06-12-19-45-21",
        IAMDatabaseAuthenticationEnabled: false,
        CertificateDetails: {
            CAIdentifier: "rds-ca-2019",
            ValidTill: "2024-07-13T17:08:50.000Z",
        },
        DedicatedLogVolume: false,
        }
];


const createCache = (instances, instancesErr) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: instancesErr,
                    data: instances
                },
            },
        },
    };
};



describe('docdbInstanceCertificateRotated', function () {
    describe('run', function () {
        it('should PASS if DocumentDB cluster instance does not need certificate rotation', function (done) {
            const cache = createCache(describeDBInstances);
            docdbInstanceCertificateRotated.run(cache, { docdb_certificate_rotation_limit: 20 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DocumentDB cluster instance does not need certificate rotation as it expires in 29 days of 20 days limit');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if DocumentDB cluster instance does not need certificate rotation', function (done) {
            const cache = createCache(describeDBInstances);
            docdbInstanceCertificateRotated.run(cache, { docdb_certificate_rotation_limit: 40 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DocumentDB cluster instance needs certificate rotation as it expires in 29 days of 40 days limit');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if no DocumentDB Clusters Instance found', function (done) {
            const cache = createCache([]);
            docdbInstanceCertificateRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DocumentDB cluster instances found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list DocumentDB Clusters Instances', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list DocumentDB Clusters Instances" });
            docdbInstanceCertificateRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
