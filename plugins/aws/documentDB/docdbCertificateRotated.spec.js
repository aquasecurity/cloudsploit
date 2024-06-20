var expect = require('chai').expect;
var docdbInstanceCertificateRotated = require('./docdbCertificateRotated');

var certPass = new Date();
certPass.setMonth(certPass.getMonth() + 2);
var certFail = new Date();
certFail.setMonth(certFail.getMonth() - 1);

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
            ValidTill: certFail,
        },
        DedicatedLogVolume: false,
    },
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
            ValidTill: certPass,
        },
        DedicatedLogVolume: false,
    },
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
            const cache = createCache([describeDBInstances[1]]);
            docdbInstanceCertificateRotated.run(cache, { docdb_certificate_rotation_limit: 30 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should FAIL if DocumentDB cluster instance needs certificate rotation', function (done) {
            const cache = createCache([describeDBInstances[0]]);
            docdbInstanceCertificateRotated.run(cache, { docdb_certificate_rotation_limit: 30 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should PASS if no DocumentDB Clusters Instance found', function (done) {
            const cache = createCache([]);
            docdbInstanceCertificateRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
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
